"""Enrichment — resolve process-context links and inherit properties (epic #1).

Implements docs/design/car-store.md §3 over the normalized events of ONE run:

- **process → parent**: candidates are processes whose `pid` == the child's
  `ppid` and whose create time is <= the child's; the latest such wins. PID is
  reused by the OS, so this is a **heuristic** link (a definitive link needs the
  parent `_EPROCESS` pointer, which the plugin does not walk yet).
- **spoke → owning process**: two tiers. The piiat.* family plugins emit the
  owning `_EPROCESS` offset (`OwnerOffset`) — joining on it is **definitive**
  (the kernel's own pointer, immune to PID reuse). Where only a PID is
  available (built-in plugins, freed owners), the (pid, create-time window)
  join applies and stays **heuristic**.
- **inheritance**: a linked event inherits its process context — but only
  properties the object HAS in the CAR model, and only where its own value is
  null. A natively-supplied value is never overwritten.
- **host identity**: hostname/fqdn from the image's OWN registry
  (ComputerName + Tcpip Hostname/Domain/DhcpDomain) applied to every event
  whose object carries those fields — the whole image is one host. A flow's
  src_hostname/src_fqdn get the same (src = the local endpoint by the
  documented convention).
- **registry user via ProfileList**: a registry event on a SID-form user hive
  (``\\REGISTRY\\USER\\S-1-5-...``) resolves `user` through the image's OWN
  SOFTWARE-hive ProfileList mapping (SID -> ProfileImagePath basename) — the
  same-image artefact join, never a guess. File-path hives
  (``...\\Users\\<name>\\NTUSER.DAT``, ``ServiceProfiles\\<name>\\``) are
  handled at normalize time.
- **link_confidence**: "definitive" when the join key was an object identity
  (reserved for future offset-carrying spokes), "heuristic" for PID-window
  joins, null where no link was made.

Also dedupes events that describe the same object instance:
- `user_session` — windows.sessions emits one row per process in a session; the
  session logs in once. Rows collapse to one event per session guid (earliest
  create time), and the collapsed rows first feed a pid→user index used to fill
  `process.user`.
- exact (object, guid, action) duplicates across plugins — the row with the most
  populated properties wins. Flow/socket guids are the protocol+endpoint tuple
  (not the scan offset, which differs between netscan's physical and netstat's
  virtual view and is shared by dual-stack twins), so the same socket seen by
  both plugins genuinely collapses and v4/v6 twins genuinely don't.

Everything is grouped by `source_image`: joins never cross images.
"""
from __future__ import annotations

import ntpath
import re
from collections import defaultdict

from . import carmodel

# A user hive rendered in SID form: \REGISTRY\USER\S-1-5-21-...(-1001)[_Classes]
_SID_HIVE = re.compile(r"(?i)\\REGISTRY\\USER\\(S-1-5-[\d-]+?)(_Classes)?$")
# A ProfileList key: ...\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
_PROFILELIST_SID = re.compile(r"(?i)\\ProfileList\\(S-1-5-[\d-]+)$")
# One canonical name per well-known account, applied store-wide so `user` means
# the same thing in every table (plugins variously render S-1-5-18 as
# "Local System" vs its "systemprofile" profile dir, and Volatility's table
# flattens S-1-5-19/20 both to "NT Authority" — indistinguishable).
_WELL_KNOWN_SIDS = {
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
}

# Process-context properties a spoke may inherit (filtered per object by the
# CAR model, filled only where null). ppid: a spoke's CAR `ppid` means the
# parent of the process it belongs to — the owner's own ppid. uid: the owner's
# account SID — the store-wide account key; thread/file/flow/service carry a
# `uid` field (but no `sid`), so the owning process's SID is inherited into it.
_INHERIT = ["exe", "image_path", "command_line", "user", "sid", "uid",
            "fqdn", "hostname", "ppid"]


def _populated(ev: dict) -> int:
    return sum(1 for k, v in ev.items() if not k.startswith("_") and v not in (None, ""))


def _dedupe(events: list[dict]) -> list[dict]:
    """Collapse exact (image, object, guid, action) duplicates — most-populated wins."""
    best: dict[tuple, dict] = {}
    order: list[tuple] = []
    for ev in events:
        # target_guid/access_level distinguish a process's several ACCESS events
        # (same initiator guid + action); both are None on every other event.
        k = (ev.get("source_image"), ev["car_object"], ev.get("guid"),
             ev.get("car_action"), ev.get("target_guid"), ev.get("access_level"))
        if ev.get("guid") is None:
            k = k + (id(ev),)  # no identity -> never collapse
        if k not in best:
            best[k] = ev
            order.append(k)
        elif _populated(ev) > _populated(best[k]):
            best[k] = ev
    return [best[k] for k in order]


def _collapse_sessions(events: list[dict]) -> tuple[list[dict], dict]:
    """windows.sessions: one row per process -> one user_session event per session
    (earliest timestamp = the login) + a (image, pid) -> user index for
    process.user inheritance."""
    keep, sessions, user_by_pid = [], {}, {}
    for ev in events:
        if ev["car_object"] != "user_session":
            keep.append(ev)
            continue
        if ev.get("owning_pid") is not None and ev.get("user"):
            user_by_pid.setdefault((ev.get("source_image"), int(ev["owning_pid"])), ev["user"])
        if ev.get("guid") is None:
            # No logon identity (unreadable token) -> this row asserts NO login;
            # it is just one process's create time, and the process itself is
            # already in the process table. Dropped, not timelined as a phantom.
            continue
        k = (ev.get("source_image"), ev.get("guid"))
        cur = sessions.get(k)
        if cur is None or ((ev.get("timestamp") or "~") < (cur.get("timestamp") or "~")):
            sessions[k] = ev
    return keep + list(sessions.values()), user_by_pid


def _sid_user_index(events: list[dict]) -> dict:
    """(image, SID) -> username, built from the image's OWN evidence: the
    SOFTWARE hive's ProfileList keys (already in the registry plugin's default
    target list) map each profile SID to its ProfileImagePath — whose basename
    is the account (C:\\Users\\Steve -> Steve; ...\\ServiceProfiles\\LocalService
    -> LocalService). Definitive per artefact, never guessed."""
    idx = {}
    for ev in events:
        if ev["car_object"] != "registry" or ev.get("value") != "ProfileImagePath":
            continue
        m = _PROFILELIST_SID.search(str(ev.get("key") or ""))
        if not m:
            continue
        name = ntpath.basename(str(ev.get("data") or "").rstrip("\\"))
        if name:
            idx[(ev.get("source_image"), m.group(1).upper())] = name
    return idx


def _fill_user_from_sid_hive(ev: dict, sid_users: dict):
    """A registry event on a SID-form user hive (\\REGISTRY\\USER\\S-1-5-...)
    gets its `user` resolved through the ProfileList index."""
    if ev.get("user") not in (None, ""):
        return
    m = _SID_HIVE.search(str(ev.get("hive") or ""))
    if m:
        u = sid_users.get((ev.get("source_image"), m.group(1).upper()))
        if u:
            ev["user"] = u


def _collapse_mft(events: list[dict]) -> list[dict]:
    """Merge windows.mftscan.MFTScan's per-ATTRIBUTE rows into one CAR file
    `create` event per MFT record: STANDARD_INFORMATION carries the times (no
    name), FILE_NAME carries the name (longest wins — the non-8.3 form) and its
    OWN birth time. creation_time = the SI birth time; where the FILE_NAME
    birth time differs it fills previous_creation_time — the classic timestomp
    tell (the DATA is recorded; the verdict stays with the analyst).
    guid = file-mft-<record number>."""
    keep, by_rec = [], {}
    for ev in events:
        if ev.get("source_plugin") != "windows.mftscan.MFTScan":
            keep.append(ev)
            continue
        nat = ev.get("_native") or {}
        rec_no = nat.get("Record Number")
        if rec_no is None:
            continue
        by_rec.setdefault((ev.get("source_image"), rec_no), []).append(ev)
    for (image, rec_no), rows in by_rec.items():
        si = [r for r in rows if (r.get("_native") or {}).get("Attribute Type") == "STANDARD_INFORMATION"]
        fn = [r for r in rows if "FILE_NAME" in str((r.get("_native") or {}).get("Attribute Type"))]
        named = [r for r in fn if r.get("file_name")]
        name_row = max(named, key=lambda r: len(str(r["file_name"]))) if named else None
        base = (si[0] if si else (name_row or rows[0])).copy()
        base["guid"] = f"file-mft-{rec_no}"
        if name_row is not None:
            base["file_name"] = name_row["file_name"]
            base["extension"] = name_row.get("extension")
        si_created = si[0].get("creation_time") if si else None
        fn_created = name_row.get("creation_time") if name_row else None
        base["creation_time"] = si_created or fn_created
        base["timestamp"] = base["creation_time"]
        if si_created and fn_created and si_created != fn_created:
            base["previous_creation_time"] = fn_created
        keep.append(base)
    return keep


def _host_identity(events: list[dict]) -> dict:
    """image -> (hostname, fqdn), from the image's OWN registry evidence (the
    plugin's default target list already extracts both keys):
    - hostname: ...\\Control\\ComputerName\\ComputerName (boot-time name),
      falling back to ...\\ComputerName\\ActiveComputerName (the running name,
      resident even when the boot key is smeared) or
      ...\\Services\\Tcpip\\Parameters (Hostname / NV Hostname)
    - domain:   ...\\Tcpip\\Parameters Domain (preferred) else DhcpDomain
    The hostname/fqdn split follows the SAME convention as the DX_DFIR
    log2timeline processor (l2t_json_dfir resolves the image hostname once from
    preprocessing and stamps every event; the CAR layer splits on a dot):
    a dotted name IS the fqdn (hostname = its first label); otherwise
    fqdn = hostname.domain where a domain is known. Definitive per artefact —
    the whole image IS one host, so the identity applies to every event.

    windows.info carries no NetBIOS name (only kernel/OS build metadata) — the
    registry ComputerName is the sole memory-native source, so a run that omits
    the registry plugin honestly leaves hostname null rather than guessing it."""
    # host = boot-time ComputerName (authoritative); host_active = the running
    # ActiveComputerName / Tcpip Hostname fallback used only where host is absent.
    host, host_active, dom_pref, dom_fallback = {}, {}, {}, {}
    for ev in events:
        if ev["car_object"] != "registry":
            continue
        img = ev.get("source_image")
        key = str(ev.get("key") or "")
        val = str(ev.get("value") or "")
        data = ev.get("data")
        if data in (None, ""):
            continue
        if key.endswith("\\Control\\ComputerName\\ComputerName") and val == "ComputerName":
            host.setdefault(img, str(data))
        elif key.endswith("\\Control\\ComputerName\\ActiveComputerName") and val == "ComputerName":
            host_active.setdefault(img, str(data))
        elif key.endswith("\\Tcpip\\Parameters"):
            if val in ("Hostname", "NV Hostname"):
                host_active.setdefault(img, str(data))
            elif val == "Domain":
                dom_pref.setdefault(img, str(data))
            elif val == "DhcpDomain":
                dom_fallback.setdefault(img, str(data))
    out = {}
    for img in set(host) | set(host_active):
        h = host.get(img) or host_active.get(img)
        if "." in h:                       # a dotted name IS the fqdn (l2t rule)
            out[img] = (h.split(".", 1)[0], h)
            continue
        dom = dom_pref.get(img) or dom_fallback.get(img)
        out[img] = (h, f"{h}.{dom}" if dom else None)
    return out


def _is_process_create(ev: dict) -> bool:
    # process CREATE rows are the real process instances; access events also
    # live in the process object and must NOT count as processes for linking.
    return ev["car_object"] == "process" and ev.get("car_action") == "create"


def _process_index(events: list[dict]) -> dict:
    """(image, pid) -> [process CREATE events sorted by create time ascending]."""
    idx = defaultdict(list)
    for ev in events:
        if _is_process_create(ev) and ev.get("pid") is not None:
            idx[(ev.get("source_image"), int(ev["pid"]))].append(ev)
    for lst in idx.values():
        lst.sort(key=lambda e: e.get("timestamp") or "")
    return idx


def _process_offset_index(events: list[dict]) -> dict:
    """(image, _EPROCESS offset) -> process event. The offset is the process's
    kernel-object identity (kept in _native by the process plugin), so a spoke
    carrying the owning offset joins DEFINITIVELY — no PID-reuse ambiguity."""
    idx = {}
    for ev in events:
        if not _is_process_create(ev):
            continue
        off = (ev.get("_native") or {}).get("Offset")
        if off is not None:
            idx[(ev.get("source_image"), int(off))] = ev
    return idx


def _match(candidates: list[dict], ts):
    """The process instance a PID refers to at time `ts`: the latest create
    <= ts. When the event HAS a timestamp the window is authoritative — if it
    disqualifies every candidate (all created after ts), there is NO match; a
    process created later cannot own an earlier event. Only a timestamp-less
    event falls back to an unambiguous single candidate."""
    if not candidates:
        return None
    if ts:
        eligible = [c for c in candidates if (c.get("timestamp") or "") <= ts]
        return eligible[-1] if eligible else None
    return candidates[0] if len(candidates) == 1 else None


def _inherit(ev: dict, proc: dict, obj_fields: set):
    for f in _INHERIT:
        if f in obj_fields and ev.get(f) in (None, "") and proc.get(f) not in (None, ""):
            ev[f] = proc[f]


def enrich(events: list[dict]) -> list[dict]:
    """Dedupe, link, inherit. Returns the final event list for the store."""
    model = carmodel.load()
    events = _collapse_mft(events)
    events, user_by_pid = _collapse_sessions(events)
    events = _dedupe(events)
    procs = _process_index(events)
    procs_by_offset = _process_offset_index(events)
    sid_users = _sid_user_index(events)
    hosts = _host_identity(events)

    for ev in events:
        image = ev.get("source_image")
        obj_fields = set(model[ev["car_object"]]["fields"])

        # Host identity — the whole image is one host, so hostname/fqdn apply
        # to every event that has those fields (and a flow's src_* IS the local
        # endpoint by the documented convention). Fills nulls only.
        ident = hosts.get(image)
        if ident:
            hostname, fqdn = ident
            for f, v in (("hostname", hostname), ("fqdn", fqdn),
                         ("src_hostname", hostname), ("src_fqdn", fqdn)):
                if v and f in obj_fields and ev.get(f) in (None, ""):
                    ev[f] = v

        # Canonical well-known account names, store-wide: `user` must mean the
        # same string in every table for the same SID.
        canonical = _WELL_KNOWN_SIDS.get(str(ev.get("sid") or ev.get("uid") or ""))
        if canonical and "user" in obj_fields:
            ev["user"] = canonical

        if ev["car_object"] == "registry":
            _fill_user_from_sid_hive(ev, sid_users)
            continue

        if ev["car_object"] == "process" and ev.get("car_action") == "access":
            # An access EVENT rides the process object: guid is already the
            # INITIATOR's process guid; inherit the initiator's context the
            # spoke way (definitive via its own offset).
            owner = None
            if ev.get("owning_offset") is not None:
                owner = procs_by_offset.get((image, int(ev["owning_offset"])))
            if owner is not None:
                ev["owning_guid"] = owner.get("guid")
                ev["link_confidence"] = "definitive"
                _inherit(ev, owner, obj_fields)
            continue

        if ev["car_object"] == "process":
            # user from the session table (per-pid, heuristic)
            if ev.get("user") in (None, "") and ev.get("pid") is not None:
                u = user_by_pid.get((image, int(ev["pid"])))
                if u:
                    ev["user"] = u
            # parent link by (ppid, create-time window) — heuristic (PID reuse)
            if ev.get("parent_pid") is not None:
                parent = _match(procs.get((image, int(ev["parent_pid"])), []),
                                ev.get("timestamp"))
                if parent is not None and parent is not ev:
                    ev["parent_guid"] = parent.get("guid")
                    ev["link_confidence"] = "heuristic"
                    for src, dst in (("exe", "parent_exe"),
                                     ("image_path", "parent_image_path"),
                                     ("command_line", "parent_command_line")):
                        if dst in obj_fields and ev.get(dst) in (None, "") \
                                and parent.get(src) not in (None, ""):
                            ev[dst] = parent[src]
            continue

        # spoke -> owning process. Tier 1 (DEFINITIVE): the spoke carries the
        # owning _EPROCESS offset — the kernel's own pointer, immune to PID
        # reuse. Tier 2 (heuristic): the (pid, create-time window) join.
        owner, confidence = None, None
        if ev.get("owning_offset") is not None:
            owner = procs_by_offset.get((image, int(ev["owning_offset"])))
            if owner is not None:
                confidence = "definitive"
        if owner is None and ev.get("owning_pid") is not None:
            owner = _match(procs.get((image, int(ev["owning_pid"])), []),
                           ev.get("timestamp"))
            if owner is not None:
                confidence = "heuristic"
        if owner is not None:
            ev["owning_guid"] = owner.get("guid")
            ev["link_confidence"] = confidence
            _inherit(ev, owner, obj_fields)
    return events
