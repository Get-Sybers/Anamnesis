// Package enrich resolves process-context links and inherits properties over the
// normalized events of ONE run. Faithful port of piiat_mem/enrich.py.
//
//   - process -> parent: candidates are processes whose pid == the child's ppid and
//     whose create time is <= the child's; the latest wins (heuristic — PID reuse).
//   - spoke -> owning process: definitive when the spoke carries the owning _EPROCESS
//     offset (OwnerOffset), else the (pid, create-time window) join (heuristic).
//   - inheritance: a linked event inherits its process context, only for properties
//     the object HAS and only where its own value is null.
//   - host identity, registry user via ProfileList, session collapse, MFT merge,
//     and exact-duplicate dedupe — all as in the Python.
package enrich

import (
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"flashback/internal/car"
	"flashback/internal/carmodel"
	"flashback/internal/value"
)

var (
	reSIDHive        = regexp.MustCompile(`(?i)\\REGISTRY\\USER\\(S-1-5-[\d-]+?)(_Classes)?$`)
	reProfileListSID = regexp.MustCompile(`(?i)\\ProfileList\\(S-1-5-[\d-]+)$`)
)

// winBasename is ntpath.basename: the part after the last \ or / (whole string
// when neither is present).
func winBasename(s string) string {
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		return s[i+1:]
	}
	return s
}

// cloneEvent shallow-copies an event map (the base for a merged MFT record).
func cloneEvent(ev car.Event) car.Event {
	out := make(car.Event, len(ev))
	for k, v := range ev {
		out[k] = v
	}
	return out
}

// One canonical name per well-known account, applied store-wide.
var wellKnownSIDs = map[string]string{
	"S-1-5-18": "Local System",
	"S-1-5-19": "Local Service",
	"S-1-5-20": "Network Service",
}

// Process-context properties a spoke may inherit (filtered per object, filled only
// where null).
var inheritFields = []string{"exe", "image_path", "command_line", "user", "sid", "uid",
	"fqdn", "hostname", "ppid"}

// --- small helpers -----------------------------------------------------------

func img(ev car.Event) string { return value.Str(ev["source_image"]) }

func blank(v any) bool { return value.IsBlank(v) }

func sameEvent(a, b car.Event) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

func populated(ev car.Event) int {
	n := 0
	for k, v := range ev {
		if strings.HasPrefix(k, "_") {
			continue
		}
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		n++
	}
	return n
}

func nativeOf(ev car.Event) map[string]any {
	if n, ok := ev["_native"].(map[string]any); ok {
		return n
	}
	return nil
}

func isProcessCreate(ev car.Event) bool {
	return ev["car_object"] == "process" && ev["car_action"] == "create"
}

// --- dedupe ------------------------------------------------------------------

func keyPart(v any) string {
	if v == nil {
		return "\x00"
	}
	return "\x01" + value.Str(v)
}

// dedupe collapses exact (image, object, guid, action, target_guid, access_level)
// duplicates — most-populated wins, first-seen order preserved. A nil guid never
// collapses.
func dedupe(events []car.Event) []car.Event {
	best := map[string]car.Event{}
	var order []string
	uniq := 0
	for _, ev := range events {
		k := strings.Join([]string{
			keyPart(ev["source_image"]), keyPart(ev["car_object"]), keyPart(ev["guid"]),
			keyPart(ev["car_action"]), keyPart(ev["target_guid"]), keyPart(ev["access_level"]),
		}, "\x1f")
		if ev["guid"] == nil {
			uniq++
			k += "\x1f" + strconv.Itoa(uniq)
		}
		if cur, ok := best[k]; !ok {
			best[k] = ev
			order = append(order, k)
		} else if populated(ev) > populated(cur) {
			best[k] = ev
		}
	}
	out := make([]car.Event, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

// --- session collapse --------------------------------------------------------

type imgStr struct{ img, s string }

func collapseSessions(events []car.Event) ([]car.Event, map[pidKey]string) {
	var keep []car.Event
	sessions := map[imgStr]car.Event{}
	var order []imgStr
	userByPID := map[pidKey]string{}
	for _, ev := range events {
		if ev["car_object"] != "user_session" {
			keep = append(keep, ev)
			continue
		}
		if pid, ok := value.Int(ev["owning_pid"]); ok && !blank(ev["user"]) {
			k := pidKey{img(ev), pid}
			if _, seen := userByPID[k]; !seen {
				userByPID[k] = value.Str(ev["user"])
			}
		}
		if ev["guid"] == nil {
			continue // no logon identity -> asserts NO login; dropped
		}
		k := imgStr{img(ev), value.Str(ev["guid"])}
		cur, ok := sessions[k]
		if !ok {
			sessions[k] = ev
			order = append(order, k)
		} else if tsKey(ev) < tsKey(cur) {
			sessions[k] = ev
		}
	}
	for _, k := range order {
		keep = append(keep, sessions[k])
	}
	return keep, userByPID
}

// tsKey mirrors `ev.get("timestamp") or "~"` — a missing timestamp sorts last.
func tsKey(ev car.Event) string {
	if s := value.Str(ev["timestamp"]); s != "" {
		return s
	}
	return "~"
}

// --- ProfileList SID -> user -------------------------------------------------

func sidUserIndex(events []car.Event) map[imgStr]string {
	idx := map[imgStr]string{}
	for _, ev := range events {
		if ev["car_object"] != "registry" || ev["value"] != "ProfileImagePath" {
			continue
		}
		m := reProfileListSID.FindStringSubmatch(value.Str(ev["key"]))
		if m == nil {
			continue
		}
		name := winBasename(strings.TrimRight(value.Str(ev["data"]), `\`))
		if name != "" {
			idx[imgStr{img(ev), strings.ToUpper(m[1])}] = name
		}
	}
	return idx
}

func fillUserFromSIDHive(ev car.Event, sidUsers map[imgStr]string) {
	if !blank(ev["user"]) {
		return
	}
	if m := reSIDHive.FindStringSubmatch(value.Str(ev["hive"])); m != nil {
		if u, ok := sidUsers[imgStr{img(ev), strings.ToUpper(m[1])}]; ok {
			ev["user"] = u
		}
	}
}

// --- MFT merge ---------------------------------------------------------------

func collapseMFT(events []car.Event) []car.Event {
	var keep []car.Event
	byRec := map[imgStr][]car.Event{}
	var order []imgStr
	for _, ev := range events {
		if value.Str(ev["source_plugin"]) != "windows.mftscan.MFTScan" {
			keep = append(keep, ev)
			continue
		}
		nat := nativeOf(ev)
		if nat == nil || nat["Record Number"] == nil {
			continue
		}
		k := imgStr{img(ev), value.Str(nat["Record Number"])}
		if _, ok := byRec[k]; !ok {
			order = append(order, k)
		}
		byRec[k] = append(byRec[k], ev)
	}
	for _, k := range order {
		rows := byRec[k]
		var si, named []car.Event
		for _, r := range rows {
			at := value.Str(nativeOf(r)["Attribute Type"])
			if at == "STANDARD_INFORMATION" {
				si = append(si, r)
			}
			if strings.Contains(at, "FILE_NAME") && !blank(r["file_name"]) {
				named = append(named, r)
			}
		}
		var nameRow car.Event
		for _, r := range named { // longest (non-8.3) file_name wins; first on tie
			if nameRow == nil || len(value.Str(r["file_name"])) > len(value.Str(nameRow["file_name"])) {
				nameRow = r
			}
		}
		var seed car.Event
		switch {
		case len(si) > 0:
			seed = si[0]
		case nameRow != nil:
			seed = nameRow
		default:
			seed = rows[0]
		}
		base := cloneEvent(seed)
		base["guid"] = "file-mft-" + value.Str(nativeOf(seed)["Record Number"])
		if nameRow != nil {
			base["file_name"] = nameRow["file_name"]
			base["extension"] = nameRow["extension"]
		}
		var siCreated, fnCreated any
		if len(si) > 0 {
			siCreated = si[0]["creation_time"]
		}
		if nameRow != nil {
			fnCreated = nameRow["creation_time"]
		}
		created := siCreated
		if blank(created) {
			created = fnCreated
		}
		base["creation_time"] = created
		base["timestamp"] = created
		if !blank(siCreated) && !blank(fnCreated) && value.Str(siCreated) != value.Str(fnCreated) {
			base["previous_creation_time"] = fnCreated
		}
		keep = append(keep, base)
	}
	return keep
}

// --- host identity -----------------------------------------------------------

func hostIdentity(events []car.Event) map[string][2]any {
	host, hostActive, domPref, domFallback := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	setDefault := func(m map[string]string, k, v string) {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	for _, ev := range events {
		if ev["car_object"] != "registry" {
			continue
		}
		i := img(ev)
		key := value.Str(ev["key"])
		val := value.Str(ev["value"])
		if blank(ev["data"]) {
			continue
		}
		data := value.Str(ev["data"])
		switch {
		case strings.HasSuffix(key, `\Control\ComputerName\ComputerName`) && val == "ComputerName":
			setDefault(host, i, data)
		case strings.HasSuffix(key, `\Control\ComputerName\ActiveComputerName`) && val == "ComputerName":
			setDefault(hostActive, i, data)
		case strings.HasSuffix(key, `\Tcpip\Parameters`):
			switch val {
			case "Hostname", "NV Hostname":
				setDefault(hostActive, i, data)
			case "Domain":
				setDefault(domPref, i, data)
			case "DhcpDomain":
				setDefault(domFallback, i, data)
			}
		}
	}
	out := map[string][2]any{}
	imgs := map[string]bool{}
	for i := range host {
		imgs[i] = true
	}
	for i := range hostActive {
		imgs[i] = true
	}
	for i := range imgs {
		h := host[i]
		if h == "" {
			h = hostActive[i]
		}
		if strings.Contains(h, ".") { // a dotted name IS the fqdn (l2t rule)
			out[i] = [2]any{strings.SplitN(h, ".", 2)[0], h}
			continue
		}
		dom := domPref[i]
		if dom == "" {
			dom = domFallback[i]
		}
		if dom != "" {
			out[i] = [2]any{h, h + "." + dom}
		} else {
			out[i] = [2]any{h, nil}
		}
	}
	return out
}

// --- process indices ---------------------------------------------------------

type pidKey struct {
	img string
	pid int64
}
type offKey struct {
	img string
	off uint64
}

func processIndex(events []car.Event) map[pidKey][]car.Event {
	idx := map[pidKey][]car.Event{}
	for _, ev := range events {
		if !isProcessCreate(ev) {
			continue
		}
		if pid, ok := value.Int(ev["pid"]); ok {
			k := pidKey{img(ev), pid}
			idx[k] = append(idx[k], ev)
		}
	}
	for _, lst := range idx {
		sort.SliceStable(lst, func(a, b int) bool { return tsAsc(lst[a]) < tsAsc(lst[b]) })
	}
	return idx
}

// tsAsc mirrors `e.get("timestamp") or ""` for the ascending create-time sort.
func tsAsc(ev car.Event) string { return value.Str(ev["timestamp"]) }

func processOffsetIndex(events []car.Event) map[offKey]car.Event {
	idx := map[offKey]car.Event{}
	for _, ev := range events {
		if !isProcessCreate(ev) {
			continue
		}
		if off, ok := value.Uint(nativeOf(ev)["Offset"]); ok {
			idx[offKey{img(ev), off}] = ev
		}
	}
	return idx
}

// match returns the process instance a PID refers to at time ts: the latest create
// <= ts. A timestamp-less event falls back to an unambiguous single candidate.
func match(candidates []car.Event, ts any) car.Event {
	if len(candidates) == 0 {
		return nil
	}
	if s := value.Str(ts); s != "" {
		var chosen car.Event
		for _, c := range candidates { // candidates are ascending by create time
			if tsAsc(c) <= s {
				chosen = c
			}
		}
		return chosen
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return nil
}

func inherit(ev, proc car.Event, objFields map[string]bool) {
	for _, f := range inheritFields {
		if objFields[f] && blank(ev[f]) && !blank(proc[f]) {
			ev[f] = proc[f]
		}
	}
}

// Enrich dedupes, links, and inherits. Returns the final event list for the store.
func Enrich(events []car.Event) []car.Event {
	events = collapseMFT(events)
	var userByPID map[pidKey]string
	events, userByPID = collapseSessions(events)
	events = dedupe(events)
	procs := processIndex(events)
	procsByOffset := processOffsetIndex(events)
	sidUsers := sidUserIndex(events)
	hosts := hostIdentity(events)

	for _, ev := range events {
		image := img(ev)
		obj := value.Str(ev["car_object"])
		objFields := carmodel.FieldSet(obj)

		// Host identity — the whole image is one host.
		if ident, ok := hosts[image]; ok {
			hostname, fqdn := ident[0], ident[1]
			for _, hf := range []struct {
				f string
				v any
			}{{"hostname", hostname}, {"fqdn", fqdn}, {"src_hostname", hostname}, {"src_fqdn", fqdn}} {
				if !blank(hf.v) && objFields[hf.f] && blank(ev[hf.f]) {
					ev[hf.f] = hf.v
				}
			}
		}

		// Canonical well-known account names, store-wide (overrides even native).
		sidOrUID := ev["sid"]
		if blank(sidOrUID) {
			sidOrUID = ev["uid"]
		}
		if canonical, ok := wellKnownSIDs[value.Str(sidOrUID)]; ok && objFields["user"] {
			ev["user"] = canonical
		}

		if obj == "registry" {
			fillUserFromSIDHive(ev, sidUsers)
			continue
		}

		if obj == "process" && ev["car_action"] == "access" {
			var owner car.Event
			if off, ok := value.Uint(ev["owning_offset"]); ok {
				owner = procsByOffset[offKey{image, off}]
			}
			if owner != nil {
				ev["owning_guid"] = owner["guid"]
				ev["link_confidence"] = "definitive"
				inherit(ev, owner, objFields)
			}
			continue
		}

		if obj == "process" {
			if blank(ev["user"]) {
				if pid, ok := value.Int(ev["pid"]); ok {
					if u, ok := userByPID[pidKey{image, pid}]; ok {
						ev["user"] = u
					}
				}
			}
			if ppid, ok := value.Int(ev["parent_pid"]); ok {
				parent := match(procs[pidKey{image, ppid}], ev["timestamp"])
				if parent != nil && !sameEvent(parent, ev) {
					ev["parent_guid"] = parent["guid"]
					ev["link_confidence"] = "heuristic"
					for _, pf := range []struct{ src, dst string }{
						{"exe", "parent_exe"}, {"image_path", "parent_image_path"},
						{"command_line", "parent_command_line"}} {
						if objFields[pf.dst] && blank(ev[pf.dst]) && !blank(parent[pf.src]) {
							ev[pf.dst] = parent[pf.src]
						}
					}
				}
			}
			continue
		}

		// spoke -> owning process. Tier 1 (definitive): owning _EPROCESS offset.
		// Tier 2 (heuristic): the (pid, create-time window) join.
		var owner car.Event
		var confidence string
		if off, ok := value.Uint(ev["owning_offset"]); ok {
			if owner = procsByOffset[offKey{image, off}]; owner != nil {
				confidence = "definitive"
			}
		}
		if owner == nil {
			if pid, ok := value.Int(ev["owning_pid"]); ok {
				if owner = match(procs[pidKey{image, pid}], ev["timestamp"]); owner != nil {
					confidence = "heuristic"
				}
			}
		}
		if owner != nil {
			ev["owning_guid"] = owner["guid"]
			ev["link_confidence"] = confidence
			inherit(ev, owner, objFields)
		}
	}
	return events
}
