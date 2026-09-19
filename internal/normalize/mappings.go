package normalize

import (
	"flashback/internal/car"
	"flashback/internal/value"
)

// SUPERSEDES: a piiat.* plugin supersedes the built-in it improves on. When the
// NEW plugin's JSONL is present, the OLD one's is skipped at store-build time
// (thread/module/network twins mostly collapse in dedupe, but user_session
// identity changed incompatibly — re-normalizing both would double-count logons).
var SUPERSEDES = map[string]string{
	"windows.piiat.threads":  "windows.thrdscan",
	"windows.piiat.modules":  "windows.dlllist",
	"windows.piiat.network":  "windows.netscan",
	"windows.piiat.sessions": "windows.sessions",
}

// isBoundSocket: a netscan/netstat row that is a bound/listening socket, not a
// connection (LISTENING, or no real foreign endpoint).
func isBoundSocket(rec car.Record) bool {
	if value.Str(rec["State"]) == "LISTENING" {
		return true
	}
	fa := rec["ForeignAddr"]
	if fa == nil {
		return true
	}
	switch value.Str(fa) {
	case "", "*", "0.0.0.0", "::":
		return true
	}
	return false
}

// socketMap / flowMap build the shared bound-socket and connection maps, with an
// optional owning-offset field (piiat.network carries OwnerOffset; the built-ins
// do not).
func socketMap(owningOffset string) *carMap {
	return &carMap{
		object: "socket", action: "listen", ts: "Created",
		guid:         guidSpec{kind: guidFields, fields: []string{"Proto", "LocalAddr", "LocalPort", "PID"}},
		owningPID:    "PID",
		owningOffset: owningOffset,
		props: map[string]src{
			"local_address": field("LocalAddr"), "local_port": field("LocalPort"),
			"protocol": transport(field("Proto")), "family": family(field("Proto")),
			"pid": field("PID"), "success": constS(true),
		},
		keep: []string{"State", "Offset", "Owner", "ForeignAddr", "ForeignPort"},
	}
}

func flowMap(owningOffset string) *carMap {
	return &carMap{
		object: "flow", action: "start", ts: "Created",
		guid:         guidSpec{kind: guidFields, fields: []string{"Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort"}},
		owningPID:    "PID",
		owningOffset: owningOffset,
		props: map[string]src{
			"src_ip": field("LocalAddr"), "src_port": field("LocalPort"),
			"dest_ip": field("ForeignAddr"), "dest_port": field("ForeignPort"),
			"transport_protocol": transport(field("Proto")),
			"start_time":         field("Created"), "pid": field("PID"), "exe": field("Owner"),
		},
		keep: []string{"State", "Offset", "Proto"},
	}
}

func netVariants(owningOffset string) *carMap {
	return &carMap{
		variants: []variant{{pred: isBoundSocket, m: socketMap(owningOffset)}},
		def:      flowMap(owningOffset),
	}
}

// mappings: one entry per plugin. Ported from piiat_mem/mappings.py MAPPINGS.
var mappings = map[string]*carMap{
	// ---- process — the hub; identity already synthesized by the plugin -------
	"windows.piiat.processes": {
		object: "process", action: "create", ts: "CreateTime",
		guid:      guidSpec{kind: guidField, field: "Guid"},
		parentPID: "PPID",
		props: map[string]src{
			"pid": field("PID"), "ppid": field("PPID"),
			"exe":               first(basename(field("Path")), field("ImageFileName")),
			"image_path":        field("Path"),
			"command_line":      field("CommandLine"),
			"parent_exe":        basename(field("ParentPath")),
			"parent_image_path": field("ParentPath"),
			"user":              field("User"), "sid": field("Sid"), "uid": field("Sid"),
			"current_working_directory": field("Cwd"),
			"integrity_level":           field("IntegrityLevel"),
			"env_vars":                  field("EnvVars"),
		},
		keep: []string{"Offset", "ImageFileName", "LoadedDlls", "DllCount", "Hidden", "LogonId"},
	},
	// ---- process ACCESS events ----------------------------------------------
	"windows.piiat.access": {
		object: "process", action: "access", ts: "",
		guid:         guidSpec{kind: guidMarker, marker: procGUID(field("OwnerOffset"))},
		owningPID:    "PID",
		owningOffset: "OwnerOffset",
		props: map[string]src{
			"pid": field("PID"), "exe": field("ProcessName"),
			"access_level": field("GrantedAccess"),
			"target_pid":   field("TargetPid"), "target_name": field("TargetName"),
			"target_guid": procGUID(field("TargetOffset")),
		},
		keep: []string{"HandleValue"},
	},
	// ---- MFT records ---------------------------------------------------------
	"windows.mftscan.MFTScan": {
		object: "file", action: "create", ts: "Created",
		guid: guidSpec{kind: guidNone},
		props: map[string]src{
			"file_name": field("Filename"), "creation_time": field("Created"),
			"extension": ext(field("Filename")),
		},
		keep: []string{"Record Number", "Attribute Type", "MFT Type", "Modified",
			"Updated", "Accessed", "Offset", "Permissions"},
	},
	// ---- the piiat.* family: every spoke emits OwnerOffset -------------------
	"windows.piiat.threads": {
		object: "thread", action: "create", ts: "CreateTime",
		guid:         guidSpec{kind: guidFields, fields: []string{"Offset"}},
		owningPID:    "PID",
		owningOffset: "OwnerOffset",
		props: map[string]src{
			"tgt_pid": field("PID"), "tgt_tid": field("TID"),
			"start_address":     field("Win32StartAddress"),
			"start_module":      field("Win32StartPath"),
			"start_module_name": basename(field("Win32StartPath")),
			"start_function":    field("Win32StartFunction"),
			"stack_base":        field("StackBase"), "stack_limit": field("StackLimit"),
			"user_stack_base": field("UserStackBase"), "user_stack_limit": field("UserStackLimit"),
		},
		keep: []string{"ExitTime", "StartAddress", "StartPath", "StartFunction"},
	},
	"windows.piiat.modules": {
		object: "module", action: "load", ts: "LoadTime",
		guid:         guidSpec{kind: guidFields, fields: []string{"PID", "Base"}},
		owningPID:    "PID",
		owningOffset: "OwnerOffset",
		props: map[string]src{
			"module_path": field("Path"),
			"module_name": field("Name"), "base_address": field("Base"), "pid": field("PID"),
		},
		keep: []string{"Size", "LoadCount", "ProcessName"},
	},
	"windows.piiat.network": netVariants("OwnerOffset"),
	"windows.piiat.files": {
		object: "file", action: nil, ts: "",
		guid:         guidSpec{kind: guidFields, fields: []string{"FileObjectOffset", "PID"}},
		owningPID:    "PID",
		owningOffset: "OwnerOffset",
		props: map[string]src{
			"file_path": field("Path"), "file_name": basename(field("Path")),
			"extension": ext(field("Path")), "pid": field("PID"),
		},
		keep: []string{"HandleValue", "GrantedAccess", "FileObjectOffset", "ProcessName"},
	},
	"windows.piiat.sessions": {
		object: "user_session", action: "login", ts: "CreateTime",
		guid:         guidSpec{kind: guidFields, fields: []string{"LogonId"}},
		owningPID:    "PID",
		owningOffset: "OwnerOffset",
		props: map[string]src{
			"user": field("User"), "login_id": field("LogonId"), "uid": field("Sid"),
			"login_successful": constS(true),
		},
		keep: []string{"SessionId", "ProcessName", "Sid"},
	},
	// ---- thread — _ETHREAD offset is identity; owns via PID -----------------
	"windows.thrdscan": {
		object: "thread", action: "create", ts: "CreateTime",
		guid:      guidSpec{kind: guidFields, fields: []string{"Offset"}},
		owningPID: "PID",
		props: map[string]src{
			"tgt_pid": field("PID"), "tgt_tid": field("TID"),
			"start_address":     field("Win32StartAddress"),
			"start_module":      field("Win32StartPath"),
			"start_module_name": basename(field("Win32StartPath")),
		},
		keep: []string{"ExitTime", "StartAddress", "StartPath"},
	},
	// ---- module — identity is (owning pid, base) ----------------------------
	"windows.dlllist": {
		object: "module", action: "load", ts: "LoadTime",
		guid:      guidSpec{kind: guidFields, fields: []string{"PID", "Base"}},
		owningPID: "PID",
		props: map[string]src{
			"module_path": field("Path"),
			"module_name": field("Name"), "base_address": field("Base"), "pid": field("PID"),
		},
		keep: []string{"Size", "LoadCount", "Process"},
	},
	// ---- driver — kernel-global; modules offset is identity, no owner -------
	"windows.modules": {
		object: "driver", action: "load", ts: "",
		guid: guidSpec{kind: guidFields, fields: []string{"Offset"}},
		props: map[string]src{
			"image_path": field("Path"), "module_name": field("Name"), "base_address": field("Base"),
		},
		keep: []string{"Size"},
	},
	// ---- netscan/netstat — socket (bound/listening) or flow (connection) ----
	"windows.netscan": netVariants(""),
	"windows.netstat": netVariants(""),
	// ---- file — FILE_OBJECT offset is identity; no owner from filescan ------
	"windows.filescan": {
		object: "file", action: nil, ts: "",
		guid: guidSpec{kind: guidFields, fields: []string{"Offset"}},
		props: map[string]src{
			"file_path": field("Name"), "file_name": basename(field("Name")),
			"extension": ext(field("Name")),
		},
		keep: []string{},
	},
	// ---- registry — identity is (hive,key,value); user from the hive path ---
	"windows.piiat.registry": {
		object: "registry", action: "value_edit", ts: "LastWrite",
		guid: guidSpec{kind: guidFields, fields: []string{"Hive", "Key", "ValueName"}},
		props: map[string]src{
			"key": field("Key"), "value": field("ValueName"), "data": field("ValueData"),
			"new_content": field("ValueData"),
			"type":        field("ValueType"), "hive": field("Hive"), "user": userFromHive(field("Hive")),
		},
		keep: []string{},
	},
	// ---- service — service record offset is identity; host process via PID ---
	"windows.svcscan": {
		object: "service", action: nil, ts: "",
		guid:      guidSpec{kind: guidFields, fields: []string{"Offset"}},
		owningPID: "PID",
		props: map[string]src{
			"name":         field("Name"),
			"image_path":   exePath(first(field("Binary"), field("Binary (Registry)"))),
			"exe":          basename(exePath(first(field("Binary"), field("Binary (Registry)")))),
			"command_line": field("Binary (Registry)"), "pid": field("PID"),
		},
		keep: []string{"Order", "Start", "State", "Type", "Display", "Dll"},
	},
	// ---- user_session — identity is (Session ID, User Name) -----------------
	"windows.sessions": {
		object: "user_session", action: "login", ts: "Create Time",
		guid:      guidSpec{kind: guidFields, fields: []string{"Session ID", "User Name"}},
		owningPID: "Process ID",
		props: map[string]src{
			"user": field("User Name"), "login_id": field("Session ID"),
			"login_successful": constS(true),
		},
		keep: []string{"Session Type", "Process"},
	},
}
