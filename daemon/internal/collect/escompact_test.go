package collect

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// esEscaped writes a path as eslogger does: every slash escaped.
func esEscaped(path string) string { return strings.ReplaceAll(path, "/", `\/`) }

func esFullStat(mode int) string {
	return fmt.Sprintf(`{"st_dev":16777234,"st_mode":%d,"st_nlink":1,"st_ino":1152921500312767,"st_uid":501,"st_gid":20,"st_rdev":0,`+
		`"st_atimespec":"2026-10-31T12:00:00.000000000Z","st_mtimespec":"2026-10-31T12:00:00.000000000Z","st_ctimespec":"2026-10-31T12:00:00.000000000Z",`+
		`"st_birthtimespec":"2026-09-20T13:54:55.465626215Z","st_size":1234560,"st_blocks":2416,"st_blksize":4096,"st_flags":0,"st_gen":0}`, mode)
}

func esFullFile(path string) string {
	return `{"path":"` + esEscaped(path) + `","path_truncated":false,"stat":` + esFullStat(33188) + `}`
}

func esFullToken(pid int) string {
	return fmt.Sprintf(`{"asid":100015,"auid":501,"egid":20,"euid":501,"pid":%d,"pidversion":123456,"rgid":20,"ruid":501}`, pid)
}

// esFullProcess is a process object with every field eslogger writes.
func esFullProcess(pid, ppid int, exe string) string {
	return `{"audit_token":` + esFullToken(pid) + fmt.Sprintf(`,"ppid":%d,"original_ppid":%d,"group_id":%d,"session_id":100015,`, ppid, ppid, pid) +
		`"codesigning_flags":570522385,"is_platform_binary":false,"is_es_client":false,"executable":` + esFullFile(exe) +
		`,"cdhash":"0123456789ABCDEF0123456789ABCDEF01234567","signing_id":"com.example.tool","team_id":"ABCDE12345",` +
		`"start_time":"2026-11-01T03:00:00.000000Z","tty":null,"parent_audit_token":` + esFullToken(ppid) + `,"responsible_audit_token":` + esFullToken(ppid) + `}`
}

func esFullLine(eventType int, kind, body string) string {
	return fmt.Sprintf(`{"schema_version":1,"mach_time":1234567890123,"event_type":%d,"thread":{"thread_id":991122},"version":8,"seq_num":42,"process":%s,`+
		`"action_type":1,"action":{"result":{"result_type":1,"result":{"auth":0}}},"event":{%q:%s},"time":"2026-11-01T03:31:59.123456789Z","global_seq_num":4242}`,
		eventType, esFullProcess(4242, 100, "/usr/local/bin/node"), kind, body)
}

func esFullLines() map[string]string {
	agent := esFullProcess(500, 1, "/usr/local/bin/cursor-agent")
	return map[string]string{
		"open": esFullLine(10, "open", `{"fflag":16777218,"file":`+esFullFile("/Users/x/project/.env")+`}`),
		"exec": esFullLine(9, "exec", `{"target":`+esFullProcess(4243, 4242, "/usr/bin/git")+`,"args":["git","status","--porcelain={v2}"],"script":null,`+
			`"cwd":`+esFullFile("/Users/x/project")+`,"last_fd":3,"image_cputype":16777228,"image_cpusubtype":2}`),
		"unlink":            esFullLine(32, "unlink", `{"target":`+esFullFile("/Users/x/project/old.txt")+`,"parent_dir":`+esFullFile("/Users/x/project")+`}`),
		"rename existing":   esFullLine(25, "rename", `{"source":`+esFullFile("/Users/x/a.txt")+`,"destination_type":0,"destination":{"existing_file":`+esFullFile("/Users/x/b.txt")+`}}`),
		"rename new path":   esFullLine(25, "rename", `{"source":`+esFullFile("/Users/x/a.txt")+`,"destination_type":1,"destination":{"new_path":{"dir":`+esFullFile("/Users/x/Library/LaunchAgents")+`,"filename":"com.example.plist"}}}`),
		"create new path":   esFullLine(13, "create", `{"destination_type":1,"destination":{"new_path":{"dir":`+esFullFile("/Users/x/Downloads")+`,"filename":"Tool.app"}},"acl":null}`),
		"tcc modify":        esFullLine(132, "tcc_modify", `{"service":"kTCCServiceSystemPolicyAllFiles","identity":"com.example.agent","identity_type":0,"update_type":1,"instigator_token":`+esFullToken(500)+`,"instigator":`+agent+`,"responsible_token":null,"responsible":null,"right":2,"reason":5}`),
		"btm add":           esFullLine(115, "btm_launch_item_add", `{"instigator":`+agent+`,"app":null,"item":{"item_type":3,"legacy":true,"managed":false,"uid":501,"item_url":"file:\/\/\/Users\/x\/Library\/LaunchAgents\/com.example.helper.plist","app_url":""},"executable_path":"\/Users\/x\/.local\/bin\/helper","instigator_token":{"pid":500},"app_token":null}`),
		"btm remove":        esFullLine(116, "btm_launch_item_remove", `{"instigator":null,"app":null,"item":{"item_type":3,"legacy":true,"managed":false,"uid":501,"item_url":"file:\/\/\/Users\/x\/Library\/LaunchAgents\/com.example.helper.plist","app_url":null},"instigator_token":{"pid":500},"app_token":null}`),
		"xprotect":          esFullLine(118, "xp_malware_detected", `{"signature_version":"5321","malware_identifier":"MACOS.ADLOAD.A","incident_identifier":"8C1F","detected_path":"\/Users\/x\/Downloads\/installer.app","detected_executable":"\/Users\/x\/Downloads\/installer.app\/Contents\/MacOS\/installer"}`),
		"profile add":       esFullLine(122, "profile_add", `{"instigator":`+agent+`,"is_update":false,"profile":{"identifier":"com.example.proxy","uuid":"5D4C1E2A-0000-4000-8000-000000000001","install_source":1,"organization":"Example","display_name":"Example Proxy","scope":"User"},"instigator_token":{"pid":500}}`),
		"gatekeeper object": esFullLine(128, "gatekeeper_user_override", `{"file_type":1,"file":{"path":"\/Users\/x\/Downloads\/Tool.app","path_truncated":false,"stat":`+esFullStat(16877)+`},"signing_info":null,"sha256":"NULL"}`),
		"gatekeeper string": esFullLine(128, "gatekeeper_user_override", `{"file_type":0,"file":"\/Users\/x\/Downloads\/tool","sha256":null,"signing_info":null}`),
		"unknown event":     esFullLine(77, "future_event", `{"anything":{"nested":[1,{"x":"}"}]}}`),
	}
}

func assertSameParse(t *testing.T, name string, line, compact []byte) {
	t.Helper()
	want, wv := parseESLine(line)
	got, gv := parseESLine(compact)
	if wv != gv || !reflect.DeepEqual(want, got) {
		t.Fatalf("%s: compact line parses to %+v (%v), original to %+v (%v)\ncompact: %s", name, got, gv, want, wv, compact)
	}
}

// A compact line decodes to the event its eslogger line does, for every
// event type the collector subscribes to, at a fraction of its size.
func TestCompactESLineKeepsEveryParsedField(t *testing.T) {
	for name, line := range esFullLines() {
		compact, ok := CompactESLine(nil, []byte(line))
		if !ok {
			t.Fatalf("%s: not compacted: %s", name, line)
		}
		assertSameParse(t, name, []byte(line), compact)
		if name == "open" && len(compact)*4 > len(line) {
			t.Fatalf("open: compact line is %d of %d bytes: %s", len(compact), len(line), compact)
		}
	}
}

// Layout does not matter: whitespace, key case, escaped keys and strings
// holding JSON punctuation compact to the same event.
func TestCompactESLineFollowsJSONNotLayout(t *testing.T) {
	cases := map[string]string{
		"spaced":        `{ "process" : { "audit_token" : { "pid" : 7 } , "ppid" : 1 } , "event" : { "open" : { "file" : { "path" : "/w/a" } } } , "time" : "2026-11-01T00:00:00Z" }`,
		"key case":      `{"Process":{"Audit_Token":{"PID":7},"PPID":3,"Executable":{"Path":"/bin/x"}},"EVENT":{"Open":{"FFlag":2,"File":{"Path":"/w/a"}}},"Time":"2026-11-01T00:00:00Z"}`,
		"escaped key":   `{"process":{"audit_token":{"p\u0069d":7}},"event":{"open":{"file":{"path":"/w/a"}}},"t\u0069me":"2026-11-01T00:00:00Z"}`,
		"punctuation":   `{"process":{"audit_token":{"pid":7},"executable":{"path":"/w/{a},\"b\"]"}},"x":["}",{"y":"\\"}],"event":{"open":{"file":{"path":"/w/\"q\"/[x]"}}},"time":"2026-11-01T00:00:00Z"}`,
		"null event":    `{"process":{"audit_token":{"pid":7}},"event":{"open":null},"time":"2026-11-01T00:00:00Z"}`,
		"scalar object": `{"process":{"audit_token":7,"executable":"x"},"event":{"exec":{"target":{"executable":{"path":"/bin/x"}}}},"time":"2026-11-01T00:00:00Z"}`,
		"timestamp":     `{"process":{"pid":7},"event":{"unlink":{"target":{"path":"/w/a"}}},"timestamp":"2026-11-01T00:00:00Z"}`,
	}
	for name, line := range cases {
		compact, ok := CompactESLine(nil, []byte(line))
		if !ok {
			t.Fatalf("%s: not compacted", name)
		}
		assertSameParse(t, name, []byte(line), compact)
	}
}

// A line that is not one JSON object is left for the caller to keep as it
// is, and dst is unchanged.
func TestCompactESLineRejectsWhatItCannotRead(t *testing.T) {
	for _, line := range []string{
		``, `garbage`, `[1,2]`, `{"process":{"audit_token":{"pid":7}}`, `{"a":"unterminated}`, `{"a":1}{"b":2}`, `{"a" 1}`, `{"a":}`,
	} {
		dst := []byte("prefix")
		out, ok := CompactESLine(dst, []byte(line))
		if ok || string(out) != "prefix" {
			t.Fatalf("%q: compacted to %q, %v", line, out, ok)
		}
	}
}

func BenchmarkCompactESLine(b *testing.B) {
	line := []byte(esFullLines()["open"])
	var dst []byte
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for b.Loop() {
		dst, _ = CompactESLine(dst[:0], line)
	}
}
