"""Per-plugin → MITRE CAR object maps (epic #1, phase 2).

One entry per Volatility plugin: the CAR **object** it yields, the **action**, the
**timestamp** field, the **identity** that becomes the CAR `guid`, the owning
process link (an owning-PID field, resolved to `owning_guid` during enrichment),
and how each raw field maps to a canonical CAR **property**. Native fields with no
CAR home are listed in `keep` (retained in `_native`, never faked into a CAR
column) — and a canonical column is left NULL rather than filled with a
near-miss (e.g. module.image_path is the owning PROCESS's image per CAR, so the
module map leaves it null for enrichment to fill; it never puts the DLL's own
path there).

A plugin whose records split across objects declares `variants`: an ordered list
of (predicate-name, map) pairs — the first predicate that matches the record
picks the map (used by netscan/netstat: bound/listening sockets are CAR
**socket** events; actual connections are CAR **flow** events, so no direction is
ever faked onto a listener).

Identity is a **memory object offset or natural key** — never the reused PID.
Flows/sockets key on the protocol + endpoint tuple (scan offsets are not
comparable between netscan's physical and netstat's virtual view, and dual-stack
twins share one offset — the tuple is the real identity). See
docs/design/car-store.md.
"""
from __future__ import annotations

# --- property-source markers (resolved by normalize.py; markers nest) --------


def first(*fields):
    """Use the first of `fields` (field names or markers) that is non-empty."""
    return ("first", fields)


def basename(field):
    """Windows basename of a path field."""
    return ("basename", field)


def user_from_hive(field="Hive"):
    """Extract the profile user from an NTUSER.DAT / UsrClass.dat hive path."""
    return ("user_from_hive", field)


def transport(field):
    """Layer-4 protocol from Volatility's Proto ('TCPv4' -> 'TCP')."""
    return ("transport", field)


def const(value):
    """A constant the observation itself proves (e.g. a kernel socket object
    exists only after a successful bind — socket.success is true by existence)."""
    return ("const", value)


def ext(field):
    """The file extension from a path field, lowercase, no dot ('a\\b.XML' -> 'xml')."""
    return ("ext", field)


def exe_path(field):
    """The executable path parsed out of a service ImagePath-style command line
    ('"C:\\p q\\x.exe" -k net' -> 'C:\\p q\\x.exe'; '%SystemRoot%\\s\\y.exe -k n'
    -> '%SystemRoot%\\s\\y.exe'). Parsing, not guessing — the path is verbatim
    inside the string."""
    return ("exe_path", field)


def family(field):
    """Address family from Volatility's Proto ('TCPv4' -> 'ipv4')."""
    return ("family", field)


def proc_guid(field):
    """A process guid synthesized from an _EPROCESS offset field
    (proc-<hex>) — the same convention windows.piiat.processes emits."""
    return ("proc_guid", field)


# --- variant predicates (referenced by name from `variants`) -----------------

def is_bound_socket(rec) -> bool:
    """A netscan/netstat row that is a bound/listening socket, not a connection:
    LISTENING state, or no real foreign endpoint (UDP '*', 0.0.0.0, ::)."""
    if (rec.get("State") or "") == "LISTENING":
        return True
    fa = rec.get("ForeignAddr")
    return fa in (None, "", "*", "0.0.0.0", "::")


PREDICATES = {"is_bound_socket": is_bound_socket}

# A piiat.* plugin supersedes the built-in it improves on. When the NEW
# plugin's JSONL is present in a run directory, the OLD one's is skipped at
# store-build time: thread/module/network twins would mostly collapse in dedupe
# anyway (shared identity), but user_session identity changed incompatibly
# (LUID vs TS-session-number), so re-normalizing both would double-count every
# logon. One rule for all four keeps the guarantee uniform.
SUPERSEDES = {
    "windows.piiat.threads": "windows.thrdscan",
    "windows.piiat.modules": "windows.dlllist",
    "windows.piiat.network": "windows.netscan",
    "windows.piiat.sessions": "windows.sessions",
}


# --- the maps ---------------------------------------------------------------
# guid: {"field": X}  -> the record already carries the guid in field X
#       {"fields":[…]} -> synthesize `<object>-<v1>-<v2>…` (the object's identity;
#                         a None component voids the guid, but "" is legitimate —
#                         e.g. a registry key's default value has ValueName "")

_SOCKET_MAP = {
    # bound/listening socket — no connection, so no src/dest is asserted at all
    "object": "socket", "action": "listen", "ts": "Created",
    "guid": {"fields": ["Proto", "LocalAddr", "LocalPort", "PID"]},
    "owning_pid": "PID",
    "props": {
        "local_address": "LocalAddr", "local_port": "LocalPort",
        "protocol": transport("Proto"), "family": family("Proto"),
        "pid": "PID", "success": const(True),
    },
    "keep": ["State", "Offset", "Owner", "ForeignAddr", "ForeignPort"],
}
_FLOW_MAP = {
    # an actual connection. Direction is NOT knowable from a socket snapshot:
    # by convention src_* = the LOCAL endpoint and dest_* = the FOREIGN one, and
    # network_direction stays null — consumers must not infer the originator.
    "object": "flow", "action": "start", "ts": "Created",
    "guid": {"fields": ["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort"]},
    "owning_pid": "PID",
    "props": {
        "src_ip": "LocalAddr", "src_port": "LocalPort",
        "dest_ip": "ForeignAddr", "dest_port": "ForeignPort",
        "transport_protocol": transport("Proto"),
        "start_time": "Created", "pid": "PID", "exe": "Owner",
    },
    "keep": ["State", "Offset", "Proto"],
}

MAPPINGS = {
    # ---- process — the hub; identity already synthesized by the plugin -------
    "windows.piiat.processes": {
        "object": "process", "action": "create", "ts": "CreateTime",
        "guid": {"field": "Guid"}, "owning_pid": None, "parent_pid": "PPID",
        "props": {
            "pid": "PID", "ppid": "PPID",
            # CAR: `exe` is the BASENAME of image_path; ImageFileName (a 15-char
            # EPROCESS name) is a valid exe fallback but NOT a path — image_path
            # stays null when the PEB path is unavailable.
            "exe": first(basename("Path"), "ImageFileName"),
            "image_path": "Path",
            "command_line": "CommandLine",
            "parent_exe": basename("ParentPath"), "parent_image_path": "ParentPath",
            # token-derived identity (v0.4.0): the process's own SID and user —
            # native extraction, not a weak join. `uid` is the SAME token SID:
            # CAR keeps both a Windows-specific `sid` and a generic `uid`, and
            # the account's unique id in a Windows image IS its SID — so uid is
            # filled from it too (the store-wide account key the spokes inherit;
            # thread/file/flow/service have a `uid` field but no `sid` field).
            "user": "User", "sid": "Sid", "uid": "Sid",
            # completeness pass: PEB CurrentDirectory + token mandatory label
            "current_working_directory": "Cwd",
            "integrity_level": "IntegrityLevel",
            "env_vars": "EnvVars",
        },
        "keep": ["Offset", "ImageFileName", "LoadedDlls", "DllCount", "Hidden", "LogonId"],
    },
    # ---- process ACCESS events — an open Process-type handle IS an observed
    # "A holds access to B" fact (CAR process:access). guid = the INITIATING
    # process's guid per CAR; the event is distinguished from the create event
    # by its action, and from other access events by target_guid/access_level
    # (the dedupe key includes both). No timestamp -> store-only.
    "windows.piiat.access": {
        "object": "process", "action": "access", "ts": None,
        "guid": {"marker": proc_guid("OwnerOffset")},
        "owning_pid": "PID", "owning_offset": "OwnerOffset",
        "props": {
            "pid": "PID", "exe": "ProcessName",
            "access_level": "GrantedAccess",
            "target_pid": "TargetPid", "target_name": "TargetName",
            "target_guid": proc_guid("TargetOffset"),
        },
        "keep": ["HandleValue"],
    },
    # ---- MFT records — memory-resident $MFT pages carry the NTFS times the
    # FILE_OBJECT lacks. Raw rows are per-attribute (SI = times, no name;
    # FILE_NAME = name + its own times); enrichment merges them per record into
    # one file `create` event with creation_time (SI) and, where the FILE_NAME
    # attribute's birth time differs, previous_creation_time (the timestomp
    # tell — the DATA is recorded, the verdict is the analyst's).
    "windows.mftscan.MFTScan": {
        "object": "file", "action": "create", "ts": "Created",
        "guid": {"none": True}, "owning_pid": None,    # guid assigned at merge
        "props": {
            "file_name": "Filename", "creation_time": "Created",
            "extension": ext("Filename"),
        },
        "keep": ["Record Number", "Attribute Type", "MFT Type", "Modified",
                 "Updated", "Accessed", "Offset", "Permissions"],
    },
    # ---- the piiat.* family (v0.4.0): every spoke emits OwnerOffset — the
    # owning _EPROCESS address — so enrichment links DEFINITIVELY, not by PID.
    "windows.piiat.threads": {
        "object": "thread", "action": "create", "ts": "CreateTime",
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID", "owning_offset": "OwnerOffset",
        "props": {
            "tgt_pid": "PID", "tgt_tid": "TID",
            # address and module must come from the SAME source — mixing the
            # Win32 address with the kernel StartPath would assert the address
            # lives in that module (an injection false-negative). The Win32 pair
            # is the user-mode truth; the kernel pair stays in _native.
            "start_address": "Win32StartAddress",
            "start_module": "Win32StartPath",
            "start_module_name": basename("Win32StartPath"),
            # the resolved export at the user-mode start (pairs with start_module)
            "start_function": "Win32StartFunction",
            "stack_base": "StackBase", "stack_limit": "StackLimit",
            "user_stack_base": "UserStackBase", "user_stack_limit": "UserStackLimit",
        },
        "keep": ["ExitTime", "StartAddress", "StartPath", "StartFunction"],
    },
    "windows.piiat.modules": {
        "object": "module", "action": "load", "ts": "LoadTime",
        "guid": {"fields": ["PID", "Base"]}, "owning_pid": "PID", "owning_offset": "OwnerOffset",
        "props": {
            "module_path": "Path",
            "module_name": "Name", "base_address": "Base", "pid": "PID",
        },
        "keep": ["Size", "LoadCount", "ProcessName"],
    },
    "windows.piiat.network": {
        "variants": [("is_bound_socket", dict(_SOCKET_MAP, owning_offset="OwnerOffset"))],
        "default": dict(_FLOW_MAP, owning_offset="OwnerOffset"),
    },
    "windows.piiat.files": {
        # handle-enumerated files WITH owners — what filescan can never say.
        # Identity is (FILE_OBJECT, observing process): several processes may
        # hold handles to one file, and each observation is its own CAR event.
        "object": "file", "action": None, "ts": None,
        "guid": {"fields": ["FileObjectOffset", "PID"]},
        "owning_pid": "PID", "owning_offset": "OwnerOffset",
        "props": {"file_path": "Path", "file_name": basename("Path"),
                  "extension": ext("Path"), "pid": "PID"},
        "keep": ["HandleValue", "GrantedAccess", "FileObjectOffset", "ProcessName"],
    },
    "windows.piiat.sessions": {
        # one row per process; identity is the token's AuthenticationId LUID —
        # the REAL CAR login_id (persists until logout), unlike the TS session
        # number. Rows collapse to one login per LUID in enrichment.
        "object": "user_session", "action": "login", "ts": "CreateTime",
        "guid": {"fields": ["LogonId"]}, "owning_pid": "PID", "owning_offset": "OwnerOffset",
        # login_successful is proven by existence: an access token bearing this
        # AuthenticationId LUID exists only because LSA completed the logon (the
        # same "the observation proves the constant" logic as socket.success).
        "props": {"user": "User", "login_id": "LogonId", "uid": "Sid",
                  "login_successful": const(True)},
        "keep": ["SessionId", "ProcessName", "Sid"],
    },
    # ---- thread — _ETHREAD offset is identity; owns via PID -----------------
    "windows.thrdscan": {
        "object": "thread", "action": "create", "ts": "CreateTime",
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "tgt_pid": "PID", "tgt_tid": "TID",
            # paired source only (see windows.piiat.threads)
            "start_address": "Win32StartAddress",
            "start_module": "Win32StartPath",
            "start_module_name": basename("Win32StartPath"),
        },
        "keep": ["ExitTime", "StartAddress", "StartPath"],
    },
    # ---- module — identity is (owning pid, base). CAR module.image_path is the
    # OWNING PROCESS's image (enrichment fills it); module_path is the DLL's own.
    "windows.dlllist": {
        "object": "module", "action": "load", "ts": "LoadTime",
        "guid": {"fields": ["PID", "Base"]}, "owning_pid": "PID",
        "props": {
            "module_path": "Path",
            "module_name": "Name", "base_address": "Base", "pid": "PID",
        },
        "keep": ["Size", "LoadCount", "Process"],
    },
    # ---- driver — kernel-global; modules offset is identity, no owner. For a
    # driver, image_path IS the driver's own path (there is no owning process).
    "windows.modules": {
        "object": "driver", "action": "load", "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": None,
        "props": {
            "image_path": "Path", "module_name": "Name", "base_address": "Base",
        },
        "keep": ["Size"],
    },
    # ---- netscan/netstat — socket (bound/listening) or flow (connection) ----
    "windows.netscan": {"variants": [("is_bound_socket", _SOCKET_MAP)],
                        "default": _FLOW_MAP},
    "windows.netstat": {"variants": [("is_bound_socket", _SOCKET_MAP)],
                        "default": _FLOW_MAP},
    # ---- file — FILE_OBJECT offset is identity; no owner from filescan ------
    "windows.filescan": {
        "object": "file", "action": None, "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": None,
        "props": {"file_path": "Name", "file_name": basename("Name"),
                  "extension": ext("Name")},
        "keep": [],
    },
    # ---- registry — identity is (hive,key,value); user from the hive path ---
    "windows.piiat.registry": {
        # one row per registry VALUE → CAR `value_edit` (CAR split `edit` into
        # key_edit / value_edit). ValueName "" (the default value) is a
        # legitimate identity component.
        "object": "registry", "action": "value_edit", "ts": "LastWrite",
        "guid": {"fields": ["Hive", "Key", "ValueName"]}, "owning_pid": None,
        "props": {
            "key": "Key", "value": "ValueName", "data": "ValueData",
            # the row IS a value_edit at LastWrite, and the resident data is the
            # value's content AFTER that edit — exactly CAR new_content.
            "new_content": "ValueData",
            "type": "ValueType", "hive": "Hive", "user": user_from_hive("Hive"),
        },
        "keep": [],
    },
    # ---- service — service record offset is identity; host process via PID.
    # 'Binary (Registry)' is the registry ImagePath incl. arguments — exactly
    # CAR service.command_line.
    "windows.svcscan": {
        "object": "service", "action": None, "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "name": "Name",
            # Binary is null for STOPPED services; the registry ImagePath in the
            # same row carries the executable. BOTH sources can carry arguments
            # (svchost.exe -k ...), so the path is parsed out of either.
            "image_path": exe_path(first("Binary", "Binary (Registry)")),
            "exe": basename(exe_path(first("Binary", "Binary (Registry)"))),
            "command_line": "Binary (Registry)", "pid": "PID",
        },
        "keep": ["Order", "Start", "State", "Type", "Display", "Dll"],
    },
    # ---- user_session — identity is (Session ID, User Name): distinct users'
    # logons must not merge under one TS session number. Owning process via PID.
    "windows.sessions": {
        "object": "user_session", "action": "login", "ts": "Create Time",
        "guid": {"fields": ["Session ID", "User Name"]}, "owning_pid": "Process ID",
        # a session with live processes proves the logon completed (see the
        # piiat.sessions note) — login_successful is true by existence.
        "props": {"user": "User Name", "login_id": "Session ID",
                  "login_successful": const(True)},
        "keep": ["Session Type", "Process"],
    },
}
