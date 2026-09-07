"""Unit tests for the CAR pipeline: normalize -> enrich -> store -> output.

Synthetic records shaped exactly like the real plugins' JSONL (no docker needed).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from piiat_mem import carmodel, enrich, normalize, store, timeline  # noqa: E402


def _proc(pid, ppid, offset, name, path, ts, cmdline="c"):
    return normalize.normalize("windows.piiat.processes", {
        "Offset": offset, "Guid": f"proc-{offset:x}", "PID": pid, "PPID": ppid,
        "ImageFileName": name, "Path": path, "CommandLine": cmdline,
        "ParentPath": None, "CreateTime": ts, "DllCount": 0,
        "LoadedDlls": None, "Hidden": False})


def _tag(ev, image="img.mem"):
    ev["source_image"] = image
    return ev


# ---- model -----------------------------------------------------------------

def test_model_is_authoritative_13_objects():
    m = carmodel.load()
    assert len(m) == 13
    assert {"authentication", "email", "http", "socket"} <= set(m)
    assert {"guid", "parent_guid", "target_guid"} <= set(m["process"]["fields"])
    assert set(carmodel.all_fields()) >= set(m["flow"]["fields"])


# ---- normalize -------------------------------------------------------------

def test_normalize_process_exe_is_basename():
    ev = _proc(10, 4, 0xabc, "x.exe", r"C:\dir\x.exe", "2020-01-01T00:00:10+00:00")
    assert ev["car_object"] == "process" and ev["car_action"] == "create"
    assert ev["guid"] == "proc-abc"
    assert ev["exe"] == "x.exe" and ev["image_path"] == r"C:\dir\x.exe"


def test_normalize_epoch_sentinel_timestamp_dropped():
    ev = normalize.normalize("windows.thrdscan", {
        "Offset": 1, "PID": 4, "TID": 8, "CreateTime": "1601-01-01T00:00:00+00:00"})
    assert ev["timestamp"] is None
    assert ev["guid"] == "thread-1" and ev["owning_pid"] == 4


def test_normalize_registry_user_from_hive_and_action():
    ev = normalize.normalize("windows.piiat.registry", {
        "Hive": r"\??\C:\Users\jake\NTUSER.DAT", "Key": "Software\\Run",
        "ValueName": "x", "ValueData": "y", "ValueType": "REG_SZ",
        "LastWrite": "2020-01-02"})
    assert ev["car_action"] == "value_edit" and ev["user"] == "jake"


def test_normalize_unmapped_plugin_returns_none():
    assert normalize.normalize("windows.info", {"Variable": "Is64Bit"}) is None


# ---- enrich ----------------------------------------------------------------

def test_spoke_inherits_owner_and_is_marked_heuristic():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    t = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 99, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
    out = enrich.enrich([p, t])
    th = [e for e in out if e["car_object"] == "thread"][0]
    assert th["owning_guid"] == "proc-a"
    assert th["link_confidence"] == "heuristic"
    # thread has user/hostname in CAR but NOT image_path — nothing to inherit there
    assert "image_path" not in carmodel.fields("thread")


def test_pid_reuse_disambiguated_by_create_time_window():
    old = _tag(_proc(10, 4, 0xa, "old.exe", r"C:\old.exe", "2020-01-01T00:00:10+00:00"))
    new = _tag(_proc(10, 4, 0xb, "new.exe", r"C:\new.exe", "2020-01-01T09:00:00+00:00"))
    early = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 1, "PID": 10, "TID": 1, "CreateTime": "2020-01-01T00:30:00+00:00"}))
    late = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 2, "PID": 10, "TID": 2, "CreateTime": "2020-01-01T10:00:00+00:00"}))
    out = enrich.enrich([old, new, early, late])
    th = {e["tgt_tid"]: e for e in out if e["car_object"] == "thread"}
    assert th[1]["owning_guid"] == "proc-a"   # created before new.exe existed
    assert th[2]["owning_guid"] == "proc-b"   # latest create <= its time


def test_parent_link_and_parent_fields_fill_only_null():
    parent = _tag(_proc(4, 0, 0x1, "par.exe", r"C:\par.exe", "2020-01-01T00:00:01+00:00"))
    child = _tag(_proc(10, 4, 0x2, "kid.exe", r"C:\kid.exe", "2020-01-01T00:00:05+00:00"))
    out = enrich.enrich([parent, child])
    kid = [e for e in out if e.get("pid") == 10][0]
    assert kid["parent_guid"] == "proc-1"
    assert kid["parent_image_path"] == r"C:\par.exe"
    assert kid["parent_exe"] == "par.exe"
    assert kid["link_confidence"] == "heuristic"


def test_session_rows_collapse_and_feed_process_user():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    s1 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\jake", "Create Time": "2020-01-01T00:00:02+00:00",
        "Process ID": 10, "Process": "x.exe"}))
    s2 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\jake", "Create Time": "2020-01-01T00:00:09+00:00",
        "Process ID": 11, "Process": "y.exe"}))
    out = enrich.enrich([p, s1, s2])
    sessions = [e for e in out if e["car_object"] == "user_session"]
    assert len(sessions) == 1                       # collapsed to one login event
    assert sessions[0]["timestamp"] == "2020-01-01T00:00:02+00:00"
    proc = [e for e in out if e["car_object"] == "process"][0]
    assert proc["user"] == "HOST\\jake"             # filled from the session table


def test_native_value_never_overwritten():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    svc = _tag(normalize.normalize("windows.svcscan", {
        "Offset": 5, "Name": "svc", "Binary": r"C:\svc.exe", "PID": 10}))
    out = enrich.enrich([p, svc])
    s = [e for e in out if e["car_object"] == "service"][0]
    assert s["image_path"] == r"C:\svc.exe"         # native value kept
    assert s["exe"] == "svc.exe"
    assert s["owning_guid"] == "proc-a"


def test_netscan_listener_is_socket_connection_is_flow():
    listener = normalize.normalize("windows.netscan", {
        "Offset": 7, "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 3389,
        "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING",
        "PID": 10, "Owner": "svchost.exe", "Created": "2020-01-01T00:01:00+00:00"})
    conn = normalize.normalize("windows.netscan", {
        "Offset": 8, "Proto": "TCPv6", "LocalAddr": "::1", "LocalPort": 5000,
        "ForeignAddr": "2001:db8::5", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": "x.exe", "Created": "2020-01-01T00:01:01+00:00"})
    assert listener["car_object"] == "socket" and listener["car_action"] == "listen"
    assert listener["local_port"] == 3389 and listener["protocol"] == "TCP"
    assert listener["family"] == "ipv4"
    assert conn["car_object"] == "flow" and conn["transport_protocol"] == "TCP"
    assert conn["start_time"] == "2020-01-01T00:01:01+00:00"


def test_dedupe_same_socket_across_plugins_and_dualstack_twins_survive():
    # same connection seen by netscan (physical offset) and netstat (virtual
    # offset) -> ONE flow, most-populated wins; guid is the protocol+5-tuple
    a = _tag(normalize.normalize("windows.netscan", {
        "Offset": 7, "Proto": "TCPv4", "LocalAddr": "1.1.1.1", "LocalPort": 1,
        "ForeignAddr": "2.2.2.2", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": None, "Created": "2020-01-01T00:01:00+00:00"}))
    b = _tag(normalize.normalize("windows.netstat", {
        "Offset": 0xFFFF7000, "Proto": "TCPv4", "LocalAddr": "1.1.1.1", "LocalPort": 1,
        "ForeignAddr": "2.2.2.2", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": "x.exe", "Created": "2020-01-01T00:01:00+00:00"}))
    # dual-stack twins share ONE offset but differ by protocol family -> distinct
    c = _tag(normalize.normalize("windows.netscan", {
        "Offset": 7, "Proto": "TCPv6", "LocalAddr": "::1", "LocalPort": 1,
        "ForeignAddr": "2001:db8::5", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": None, "Created": "2020-01-01T00:01:00+00:00"}))
    out = enrich.enrich([a, b, c])
    flows = [e for e in out if e["car_object"] == "flow"]
    assert len(flows) == 2
    v4 = [f for f in flows if f["src_ip"] == "1.1.1.1"][0]
    assert v4["exe"] == "x.exe"          # most-populated (netstat) row won


def test_module_image_path_left_null_then_inherited_from_owner():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\dir\x.exe", "2020-01-01T00:00:10+00:00"))
    m = _tag(normalize.normalize("windows.dlllist", {
        "PID": 10, "Process": "x.exe", "Base": 0x7ff0, "Name": "ntdll.dll",
        "Path": r"C:\Windows\SYSTEM32\ntdll.dll", "LoadTime": "2020-01-01T00:00:11+00:00"}))
    assert m.get("image_path") is None                # never the DLL's own path
    assert m["module_path"] == r"C:\Windows\SYSTEM32\ntdll.dll"
    out = enrich.enrich([p, m])
    mod = [e for e in out if e["car_object"] == "module"][0]
    assert mod["image_path"] == r"C:\dir\x.exe"       # inherited: the LOADER's image
    assert mod["owning_guid"] == "proc-a"


def test_registry_user_from_sid_hive_via_profilelist():
    profile = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\SystemRoot\System32\Config\SOFTWARE",
        "Key": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
               r"\ProfileList\S-1-5-21-1474204758-2504895174-1356074821-1001",
        "ValueName": "ProfileImagePath", "ValueData": r"C:\Users\Steve",
        "ValueType": "REG_EXPAND_SZ", "LastWrite": "2019-01-28"}))
    sid_row = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\USER\S-1-5-21-1474204758-2504895174-1356074821-1001",
        "Key": r"...\Software\Microsoft\Windows\CurrentVersion\Run",
        "ValueName": "x", "ValueData": "y", "ValueType": "REG_SZ",
        "LastWrite": "2019-01-29"}))
    classes_row = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\USER\S-1-5-21-1474204758-2504895174-1356074821-1001_Classes",
        "Key": r"...\ms-settings\shell\open\command", "ValueName": "",
        "ValueData": "cmd.exe", "ValueType": "REG_SZ", "LastWrite": "2019-01-29"}))
    assert sid_row["user"] is None                    # not resolvable at normalize time
    out = enrich.enrich([profile, sid_row, classes_row])
    by_key = {e["key"]: e for e in out if e["car_object"] == "registry"}
    assert by_key[sid_row["key"]]["user"] == "Steve"          # via ProfileList
    assert by_key[classes_row["key"]]["user"] == "Steve"      # _Classes twin too
    assert by_key[profile["key"]]["user"] is None             # machine hive stays null


def test_registry_user_from_serviceprofiles_path():
    ev = normalize.normalize("windows.piiat.registry", {
        "Hive": r"\??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT",
        "Key": r"...\Software\Classes", "ValueName": "x", "ValueData": "y",
        "ValueType": "REG_SZ", "LastWrite": "2019-01-28"})
    assert ev["user"] == "NetworkService"


def test_registry_default_value_keeps_its_guid():
    ev = normalize.normalize("windows.piiat.registry", {
        "Hive": "SOFTWARE", "Key": "Microsoft\\Windows\\Run", "ValueName": "",
        "ValueData": "x", "ValueType": "REG_SZ", "LastWrite": "2020-01-02"})
    assert ev["guid"] == "registry-SOFTWARE-Microsoft\\Windows\\Run-"


def test_match_never_links_to_a_later_created_process():
    late = _tag(_proc(10, 4, 0xb, "late.exe", r"C:\late.exe", "2020-01-01T09:00:00+00:00"))
    early_thread = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 1, "PID": 10, "TID": 1, "CreateTime": "2020-01-01T00:30:00+00:00"}))
    out = enrich.enrich([late, early_thread])
    th = [e for e in out if e["car_object"] == "thread"][0]
    assert th["owning_guid"] is None                  # sole candidate created AFTER
    assert th["link_confidence"] is None


def test_distinct_users_same_session_id_do_not_merge():
    s1 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\alice", "Create Time": "2020-01-01T00:00:02+00:00",
        "Process ID": 10, "Process": "x.exe"}))
    s2 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\bob", "Create Time": "2020-01-01T00:00:05+00:00",
        "Process ID": 11, "Process": "y.exe"}))
    out = enrich.enrich([s1, s2])
    assert len([e for e in out if e["car_object"] == "user_session"]) == 2


def test_process_image_path_never_a_bare_name():
    ev = _proc(10, 4, 0xa, "truncatedname14", None, "2020-01-01T00:00:10+00:00")
    assert ev["image_path"] is None                   # no faked path from EPROCESS name
    assert ev["exe"] == "truncatedname14"             # exe fallback is fine


# ---- the piiat.* family: definitive owner links (v0.4.0) -------------------

def test_owning_offset_links_definitively():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    t = _tag(normalize.normalize("windows.piiat.threads", {
        "Offset": 99, "OwnerOffset": 0xa, "PID": 10, "TID": 7,
        "CreateTime": "2020-01-01T00:00:20+00:00",
        "StackBase": 1000, "StackLimit": 900, "UserStackBase": 2000, "UserStackLimit": 1900}))
    out = enrich.enrich([p, t])
    th = [e for e in out if e["car_object"] == "thread"][0]
    assert th["owning_guid"] == "proc-a"
    assert th["link_confidence"] == "definitive"
    assert th["stack_base"] == 1000 and th["user_stack_limit"] == 1900


def test_owning_offset_miss_falls_back_to_pid_heuristic():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    t = _tag(normalize.normalize("windows.piiat.threads", {
        "Offset": 99, "OwnerOffset": 0xdead, "PID": 10, "TID": 7,   # freed owner
        "CreateTime": "2020-01-01T00:00:20+00:00"}))
    out = enrich.enrich([p, t])
    th = [e for e in out if e["car_object"] == "thread"][0]
    assert th["owning_guid"] == "proc-a"
    assert th["link_confidence"] == "heuristic"


def test_piiat_files_event_per_process_observation():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    f1 = _tag(normalize.normalize("windows.piiat.files", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "HandleValue": 4,
        "FileObjectOffset": 0xF11E, "Path": r"\Device\HarddiskVolume2\secret.docx",
        "GrantedAccess": 3}))
    f2 = _tag(normalize.normalize("windows.piiat.files", {
        "OwnerOffset": 0xb, "PID": 11, "ProcessName": "y.exe", "HandleValue": 8,
        "FileObjectOffset": 0xF11E, "Path": r"\Device\HarddiskVolume2\secret.docx",
        "GrantedAccess": 1}))
    assert f1["guid"] != f2["guid"]        # per-(file, process) observation
    out = enrich.enrich([p, f1, f2])
    files = [e for e in out if e["car_object"] == "file"]
    assert len(files) == 2                 # both observations survive
    owned = [e for e in files if e["owning_guid"] == "proc-a"][0]
    assert owned["link_confidence"] == "definitive"
    assert owned["file_name"] == "secret.docx" and owned["pid"] == 10


def test_piiat_sessions_luid_identity_and_native_process_user():
    p = normalize.normalize("windows.piiat.processes", {
        "Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
        "ImageFileName": "x.exe", "Path": r"C:\x.exe", "CommandLine": "c",
        "ParentPath": None, "CreateTime": "2020-01-01T00:00:10+00:00",
        "DllCount": 0, "LoadedDlls": None, "Hidden": False,
        "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve", "LogonId": "0x338f0"})
    assert p["user"] == "Steve" and p["sid"] == "S-1-5-21-1-2-3-1001"  # native
    s1 = _tag(normalize.normalize("windows.piiat.sessions", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
        "LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
        "CreateTime": "2020-01-01T00:00:10+00:00"}))
    s2 = _tag(normalize.normalize("windows.piiat.sessions", {
        "OwnerOffset": 0xb, "PID": 11, "ProcessName": "y.exe", "SessionId": 1,
        "LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
        "CreateTime": "2020-01-01T00:00:30+00:00"}))
    s3 = _tag(normalize.normalize("windows.piiat.sessions", {
        "OwnerOffset": 0xc, "PID": 12, "ProcessName": "svc.exe", "SessionId": 0,
        "LogonId": "0x3e7", "Sid": "S-1-5-18", "User": "Local System",
        "CreateTime": "2020-01-01T00:00:01+00:00"}))
    out = enrich.enrich([_tag(p), s1, s2, s3])
    sessions = sorted((e for e in out if e["car_object"] == "user_session"),
                      key=lambda e: e["login_id"])
    assert [s["login_id"] for s in sessions] == ["0x338f0", "0x3e7"]  # one per LUID
    steve = [s for s in sessions if s["login_id"] == "0x338f0"][0]
    assert steve["timestamp"] == "2020-01-01T00:00:10+00:00"  # earliest = login
    assert steve["uid"] == "S-1-5-21-1-2-3-1001"


def test_superseded_builtin_jsonl_skipped_when_piiat_output_present(tmp_path):
    import json as _json
    from piiat_mem import cli
    plug = tmp_path / "plugins"; plug.mkdir()
    # old windows.sessions rows AND new piiat.sessions rows for the SAME logon
    (plug / "windows.sessions.jsonl").write_text(_json.dumps({
        "Session ID": 1, "User Name": "HOST\\Steve", "Process ID": 10,
        "Process": "x.exe", "Create Time": "2019-01-28T19:40:32+00:00"}) + "\n")
    (plug / "windows.piiat.sessions.jsonl").write_text(_json.dumps({
        "OwnerOffset": 10, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
        "LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
        "CreateTime": "2019-01-28T19:40:32+00:00"}) + "\n")
    st = cli.build_store(str(tmp_path), "img.mem")
    assert st.counts().get("user_session") == 1        # no double-counted logon
    row = next(st.iter_object("user_session"))
    assert row["login_id"] == "0x338f0"                # the LUID identity won
    st.close()


def test_well_known_sid_user_is_canonical_store_wide():
    p = normalize.normalize("windows.piiat.processes", {
        "Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
        "ImageFileName": "svc.exe", "Path": r"C:\svc.exe", "CommandLine": "c",
        "ParentPath": None, "CreateTime": "2020-01-01T00:00:10+00:00",
        "DllCount": 0, "LoadedDlls": None, "Hidden": False,
        "Sid": "S-1-5-19", "User": "NT Authority", "LogonId": "0x3e5"})
    s = normalize.normalize("windows.piiat.sessions", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "svc.exe", "SessionId": 0,
        "LogonId": "0x3e5", "Sid": "S-1-5-19", "User": "LocalService",
        "CreateTime": "2020-01-01T00:00:10+00:00"})
    out = enrich.enrich([_tag(p), _tag(s)])
    users = {e["car_object"]: e["user"] for e in out}
    assert users["process"] == "Local Service"          # canonical, both tables
    assert users["user_session"] == "Local Service"


def test_tokenless_session_row_is_not_a_phantom_login():
    s = _tag(normalize.normalize("windows.piiat.sessions", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
        "LogonId": None, "Sid": None, "User": None,
        "CreateTime": "2020-01-01T00:00:10+00:00"}))
    out = enrich.enrich([s])
    assert [e for e in out if e["car_object"] == "user_session"] == []


def test_thread_start_module_never_mixed_source():
    ev = normalize.normalize("windows.piiat.threads", {
        "Offset": 1, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00",
        "Win32StartAddress": 0xBAD, "Win32StartPath": None,   # injected: unbacked
        "StartAddress": 0x100, "StartPath": r"\Windows\System32\ntdll.dll"})
    assert ev["start_address"] == 0xBAD
    assert ev.get("start_module") is None               # never the kernel pair's module
    assert ev["_native"]["StartPath"] == r"\Windows\System32\ntdll.dll"


def test_host_identity_fills_every_object_from_image_registry():
    comp = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\MACHINE\SYSTEM",
        "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName",
        "ValueName": "ComputerName", "ValueData": "DESKTOP-8", "ValueType": "REG_SZ",
        "LastWrite": "2019-01-28"}))
    dom = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\MACHINE\SYSTEM",
        "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters",
        "ValueName": "DhcpDomain", "ValueData": "localdomain", "ValueType": "REG_SZ",
        "LastWrite": "2019-01-28"}))
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    t = _tag(normalize.normalize("windows.piiat.threads", {
        "Offset": 9, "OwnerOffset": 0xa, "PID": 10, "TID": 7,
        "CreateTime": "2020-01-01T00:00:20+00:00"}))
    fl = _tag(normalize.normalize("windows.piiat.network", {
        "Offset": 8, "OwnerOffset": 0xa, "Proto": "TCPv4", "LocalAddr": "10.0.0.2",
        "LocalPort": 5000, "ForeignAddr": "1.2.3.4", "ForeignPort": 443,
        "State": "ESTABLISHED", "PID": 10, "Owner": "x.exe",
        "Created": "2020-01-01T00:01:00+00:00"}))
    out = enrich.enrich([comp, dom, p, t, fl])
    by = {e["car_object"]: e for e in out}
    assert by["process"]["hostname"] == "DESKTOP-8"
    assert by["process"]["fqdn"] == "DESKTOP-8.localdomain"
    assert by["thread"]["hostname"] == "DESKTOP-8"       # thread has no fqdn field
    assert by["registry"]["hostname"] == "DESKTOP-8"
    assert by["flow"]["src_hostname"] == "DESKTOP-8"     # src = the local endpoint
    assert by["flow"].get("dest_hostname") is None       # never asserted for remote


def test_dotted_computername_is_the_fqdn_l2t_rule():
    comp = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\MACHINE\SYSTEM",
        "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName",
        "ValueName": "ComputerName", "ValueData": "HOST1.EXAMPLE.COM",
        "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    out = enrich.enrich([comp, p])
    proc = [e for e in out if e["car_object"] == "process"][0]
    assert proc["hostname"] == "HOST1"                   # first label
    assert proc["fqdn"] == "HOST1.EXAMPLE.COM"           # the dotted name IS the fqdn


def test_ls24_netbios_name_stamped_on_every_row_from_registry():
    # The real LS24 dump's ComputerName is DESKTOP-M913391. A registry row shaped
    # exactly like windows.piiat.registry emits (Key = <hive>\...\ComputerName\
    # ComputerName, ValueName ComputerName) must stamp it as hostname on EVERY
    # object that has a hostname field — the whole image is one host.
    comp = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\MACHINE\SYSTEM",
        "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName",
        "ValueName": "ComputerName", "ValueData": "DESKTOP-M913391",
        "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    m = _tag(normalize.normalize("windows.piiat.modules", {
        "OwnerOffset": 0xa, "PID": 10, "Base": 0x7ff0, "Name": "ntdll.dll",
        "Path": r"C:\Windows\System32\ntdll.dll", "LoadTime": "2020-01-01T00:00:11+00:00"}))
    out = enrich.enrich([comp, p, m])
    by = {e["car_object"]: e for e in out}
    assert by["process"]["hostname"] == "DESKTOP-M913391"
    assert by["module"]["hostname"] == "DESKTOP-M913391"   # spoke stamped too
    assert by["registry"]["hostname"] == "DESKTOP-M913391"  # the source row too
    # no domain evidence -> fqdn is an honest null, not a fabricated one
    assert by["process"].get("fqdn") is None


def test_active_computername_is_the_hostname_fallback():
    # The boot-time ComputerName key is absent/smeared, but the running
    # ActiveComputerName subkey is resident — it still yields the host name.
    active = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\MACHINE\SYSTEM",
        "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ActiveComputerName",
        "ValueName": "ComputerName", "ValueData": "DESKTOP-M913391",
        "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    out = enrich.enrich([active, p])
    proc = [e for e in out if e["car_object"] == "process"][0]
    assert proc["hostname"] == "DESKTOP-M913391"


def test_boot_computername_wins_over_active_fallback():
    boot = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\MACHINE\SYSTEM",
        "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName",
        "ValueName": "ComputerName", "ValueData": "BOOTNAME",
        "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
    active = _tag(normalize.normalize("windows.piiat.registry", {
        "Hive": r"\REGISTRY\MACHINE\SYSTEM",
        "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ActiveComputerName",
        "ValueName": "ComputerName", "ValueData": "RENAMED",
        "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    out = enrich.enrich([boot, active, p])
    proc = [e for e in out if e["car_object"] == "process"][0]
    assert proc["hostname"] == "BOOTNAME"    # authoritative boot-time name wins


def test_no_registry_leaves_hostname_honestly_null():
    # windows.info carries no NetBIOS name; with no registry evidence hostname
    # stays null rather than being faked from the dump filename.
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    out = enrich.enrich([p])
    assert out[0].get("hostname") is None and out[0].get("fqdn") is None


# ---- field-completeness pass: uid, login_successful ------------------------

def test_login_successful_true_by_existence():
    s = _tag(normalize.normalize("windows.piiat.sessions", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
        "LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
        "CreateTime": "2020-01-01T00:00:10+00:00"}))
    out = enrich.enrich([s])
    sess = [e for e in out if e["car_object"] == "user_session"][0]
    assert sess["login_successful"] is True     # a live token proves the logon
    # built-in windows.sessions asserts it too
    b = normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\jake", "Create Time": "2020-01-01T00:00:02+00:00",
        "Process ID": 10, "Process": "x.exe"})
    assert b["login_successful"] is True


def test_process_uid_from_sid_and_spokes_inherit_it():
    # process carries uid = its token SID (the generic account key); a
    # thread/file spoke — which has a `uid` field but no `sid` field — inherits
    # that SID into uid via the definitive owner link.
    p = _tag(normalize.normalize("windows.piiat.processes", {
        "Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
        "ImageFileName": "x.exe", "Path": r"C:\x.exe", "CommandLine": "c",
        "ParentPath": None, "CreateTime": "2020-01-01T00:00:10+00:00",
        "DllCount": 0, "LoadedDlls": None, "Hidden": False,
        "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve", "LogonId": "0x338f0"}))
    assert p["uid"] == "S-1-5-21-1-2-3-1001" and p["sid"] == "S-1-5-21-1-2-3-1001"
    t = _tag(normalize.normalize("windows.piiat.threads", {
        "Offset": 9, "OwnerOffset": 0xa, "PID": 10, "TID": 7,
        "CreateTime": "2020-01-01T00:00:20+00:00"}))
    f = _tag(normalize.normalize("windows.piiat.files", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "HandleValue": 4,
        "FileObjectOffset": 0xF11E, "Path": r"\Device\HarddiskVolume2\secret.docx",
        "GrantedAccess": 3}))
    out = enrich.enrich([p, t, f])
    by = {e["car_object"]: e for e in out}
    assert "sid" not in carmodel.fields("thread")   # uid is the only SID home
    assert by["thread"]["uid"] == "S-1-5-21-1-2-3-1001"
    assert by["file"]["uid"] == "S-1-5-21-1-2-3-1001"
    assert by["file"]["user"] == "Steve"            # name inherited alongside


def test_malfind_overlay_retrieves_stored_process_not_persisted(tmp_path):
    import json as _json
    from piiat_mem import cli
    # a real dump run leaves the process JSONL + the malfind JSONL on disk
    plug = tmp_path / "plugins"; plug.mkdir()
    (plug / "windows.piiat.processes.jsonl").write_text(_json.dumps({
        "Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
        "ImageFileName": "MsMpEng.exe", "Path": r"C:\W\MsMpEng.exe", "CommandLine": "c",
        "ParentPath": None, "CreateTime": "2020-01-01T00:00:10+00:00", "DllCount": 0,
        "LoadedDlls": None, "Hidden": False, "Sid": None, "User": None, "LogonId": None,
        "Cwd": None, "IntegrityLevel": None, "EnvVars": None}) + "\n")
    (plug / "windows.malfind.jsonl").write_text(_json.dumps({
        "PID": 10, "Process": "MsMpEng.exe", "Start VPN": 0x1a0000, "End VPN": 0x1a0fff,
        "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS", "CommitCharge": 1,
        "PrivateMemory": 1, "Disasm": "56 57", "Hexdump": "56 57"}) + "\n")
    st = cli.build_store(str(tmp_path), "img.mem")

    # malfind is NOT persisted — the store has ONLY the process, no malfind module row
    assert st.counts().get("module") is None
    assert all(m["source_plugin"] != "windows.malfind" for m in st.iter_object("module"))

    # the overlay RETRIEVES the stored process to populate the timeline entry
    ov = timeline.malfind_overlay(st, str(tmp_path))
    assert len(ov) == 1
    e = ov[0]
    assert e["car_object"] == "module" and e["car_action"] == "load"
    assert e["owning_guid"] == "proc-a"                      # the stored process
    assert e["image_path"] == r"C:\W\MsMpEng.exe"           # retrieved, not from malfind
    assert e["timestamp"] == "2020-01-01T00:00:10+00:00"    # the stored create time
    assert e["base_address"] == 0x1a0000                     # region detail from malfind
    assert e["_native"]["Protection"] == "PAGE_EXECUTE_READWRITE"

    # and it lands on the written timeline
    tl_path = str(tmp_path / "timeline.json")
    timeline.write_timeline_json(st, tl_path, out_dir=str(tmp_path))
    tl = [_json.loads(l) for l in open(tl_path)]
    mf = [r for r in tl if r["source_plugin"] == "windows.malfind"]
    assert len(mf) == 1 and mf[0]["owning_guid"] == "proc-a"
    st.close()


def test_process_env_vars_and_thread_start_function_mapped():
    p = normalize.normalize("windows.piiat.processes", {
        "Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
        "ImageFileName": "x.exe", "Path": r"C:\x.exe", "CommandLine": "c",
        "ParentPath": None, "CreateTime": "2020-01-01T00:00:10+00:00",
        "DllCount": 0, "LoadedDlls": None, "Hidden": False, "Sid": None,
        "User": None, "LogonId": None, "Cwd": r"C:\Users\x",
        "IntegrityLevel": "high", "EnvVars": "PATH=C:\\; TEMP=C:\\Temp"})
    assert p["env_vars"] == "PATH=C:\\; TEMP=C:\\Temp"
    t = normalize.normalize("windows.piiat.threads", {
        "Offset": 1, "OwnerOffset": 0xa, "PID": 10, "TID": 7,
        "CreateTime": "2020-01-01T00:00:20+00:00",
        "Win32StartAddress": 0x140, "Win32StartPath": r"\Windows\System32\mssrch.dll",
        "Win32StartFunction": "DllCanUnloadNow+0x10",
        "StartPath": r"\Windows\System32\ntdll.dll", "StartFunction": "RtlUserThreadStart"})
    assert t["start_function"] == "DllCanUnloadNow+0x10"      # the Win32 (user) start
    assert t["start_module"] == r"\Windows\System32\mssrch.dll"
    assert t["_native"]["StartFunction"] == "RtlUserThreadStart"  # kernel wrapper kept


def test_access_events_ride_process_with_target_identity():
    p = _tag(_proc(10, 4, 0xa, "csrss.exe", r"C:\W\csrss.exe", "2020-01-01T00:00:10+00:00"))
    a1 = _tag(normalize.normalize("windows.piiat.access", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "csrss.exe", "HandleValue": 756,
        "GrantedAccess": 0x1FFFFF, "TargetOffset": 0xb, "TargetPid": 996,
        "TargetName": "svchost.exe"}))
    a2 = _tag(normalize.normalize("windows.piiat.access", {
        "OwnerOffset": 0xa, "PID": 10, "ProcessName": "csrss.exe", "HandleValue": 900,
        "GrantedAccess": 0x1FFFFF, "TargetOffset": 0xc, "TargetPid": 700,
        "TargetName": "lsass.exe"}))
    assert a1["car_object"] == "process" and a1["car_action"] == "access"
    assert a1["guid"] == "proc-a"                     # CAR: guid = the INITIATOR
    assert a1["target_guid"] == "proc-b"
    out = enrich.enrich([p, a1, a2])
    acc = [e for e in out if e.get("car_action") == "access"]
    assert len(acc) == 2                              # distinct targets never collapse
    assert all(e["link_confidence"] == "definitive" for e in acc)
    assert all(e["image_path"] == r"C:\W\csrss.exe" for e in acc)  # initiator context
    assert {e["target_name"] for e in acc} == {"svchost.exe", "lsass.exe"}


def test_mft_rows_merge_into_one_create_event_with_timestomp_tell():
    si = _tag(normalize.normalize("windows.mftscan.MFTScan", {
        "Offset": 1, "Record Type": "FILE", "Record Number": 99107, "Link Count": 1,
        "MFT Type": "File", "Permissions": "a", "Attribute Type": "STANDARD_INFORMATION",
        "Created": "2015-01-01T00:00:00+00:00",       # stomped (backdated)
        "Modified": "2019-01-29T04:27:51+00:00", "Updated": None, "Accessed": None,
        "Filename": None}))
    fn1 = _tag(normalize.normalize("windows.mftscan.MFTScan", {
        "Offset": 1, "Record Type": "FILE", "Record Number": 99107, "Link Count": 1,
        "MFT Type": "File", "Permissions": "a", "Attribute Type": "FILE_NAME",
        "Created": "2019-01-29T04:27:51+00:00", "Modified": None, "Updated": None,
        "Accessed": None, "Filename": "CSS_1_~1.CSS"}))
    fn2 = _tag(normalize.normalize("windows.mftscan.MFTScan", {
        "Offset": 1, "Record Type": "FILE", "Record Number": 99107, "Link Count": 1,
        "MFT Type": "File", "Permissions": "a", "Attribute Type": "FILE_NAME",
        "Created": "2019-01-29T04:27:51+00:00", "Modified": None, "Updated": None,
        "Accessed": None, "Filename": "evil-css[1].css"}))
    out = enrich.enrich([si, fn1, fn2])
    files = [e for e in out if e["car_object"] == "file"]
    assert len(files) == 1                            # one event per MFT record
    f = files[0]
    assert f["guid"] == "file-mft-99107"
    assert f["file_name"] == "evil-css[1].css"        # longest (non-8.3) name wins
    assert f["extension"] == "css"
    assert f["creation_time"] == "2015-01-01T00:00:00+00:00"          # SI
    assert f["previous_creation_time"] == "2019-01-29T04:27:51+00:00" # FN differs
    assert f["timestamp"] == f["creation_time"] and f["car_action"] == "create"


# ---- store + output --------------------------------------------------------

def test_store_and_outputs(tmp_path):
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    f = _tag(normalize.normalize("windows.filescan", {"Offset": 3, "Name": r"\x\y.txt"}))
    t = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 9, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
    events = enrich.enrich([p, f, t])

    st = store.CarStore(str(tmp_path / "car.db"))
    assert st.insert_events(events) == 3
    st.insert_context("img.mem", "windows.info", [{"Variable": "Is64Bit", "Value": "True"}])

    assert st.counts() == {"process": 1, "file": 1, "thread": 1}
    # file has no timestamp -> store-only, not timelined
    tl = list(st.iter_timeline())
    assert [e["car_object"] for e in tl] == ["process", "thread"]

    # wide JSONL: every CAR property present on every row, null or not
    tl_path = str(tmp_path / "timeline.json")
    n = timeline.write_timeline_json(st, tl_path)
    assert n == 2
    rows = [json.loads(l) for l in open(tl_path)]
    superset = set(carmodel.all_fields())
    for row in rows:
        assert {"timestamp", "car_object", "car_action", "guid"} <= set(row)
        assert superset <= set(row)                 # every property, null or not
    assert rows[0]["car_object"] == "process" and rows[1]["car_object"] == "thread"
    assert rows[1]["owning_guid"] == "proc-a"

    # per-object CSVs: one per populated object, with that object's properties
    written = timeline.write_object_csvs(st, str(tmp_path / "car"))
    assert set(written) == {"process", "file", "thread"}
    head = open(tmp_path / "car" / "process.csv").readline().strip().split(",")
    assert "command_line" in head and "guid" in head and "car_object" not in head
    st.close()
