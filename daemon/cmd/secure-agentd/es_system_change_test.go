package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
)

// esProcessJSON is an eslogger es_process_t with the fields the daemon reads.
func esProcessJSON(pid, ppid int, exe string) string {
	return fmt.Sprintf(`{"audit_token":{"pid":%d,"euid":501},"ppid":%d,"executable":{"path":%q}}`, pid, ppid, exe)
}

// esSystemLine is one eslogger line whose message process is proc and whose
// event body is body under name.
func esSystemLine(name, proc, body string) string {
	return esSystemLineAt("2026-10-28T21:00:00.000000000Z", name, proc, body)
}

// esSystemLineAt is esSystemLine at time at.
func esSystemLineAt(at, name, proc, body string) string {
	return fmt.Sprintf(`{"version":8,"time":%q,"event_type":0,"process":%s,"event":{%q:%s}}`, at, proc, name, body)
}

// esEscapeSlashes writes a line the way eslogger does: every "/" in its JSON
// strings as "\/".
func esEscapeSlashes(line string) string {
	return strings.ReplaceAll(line, "/", `\/`)
}

// System-change events in the privileged spool reach the store as flags: the
// agent that instigated a background item, profile or Gatekeeper change, and
// every XProtect detection. The BTM daemon's own registrations do not flag.
func TestSpoolSystemChangeEventsRaiseFlags(t *testing.T) {
	btmd := esProcessJSON(300, 1, "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd")
	xprotect := esProcessJSON(301, 1, "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect")
	agent := esProcessJSON(500, 1, "/usr/local/bin/cursor-agent")
	lines := []string{
		esSystemLine("btm_launch_item_add", btmd,
			`{"instigator":`+agent+`,"app":null,"item":{"item_type":3,"legacy":true,"managed":false,"uid":501,"item_url":"file:///Users/x/Library/LaunchAgents/com.example.helper.plist","app_url":""},"executable_path":"/Users/x/.local/bin/helper","instigator_token":{"pid":500},"app_token":null}`),
		esSystemLine("btm_launch_item_add", btmd,
			`{"instigator":null,"app":null,"item":{"item_type":3,"legacy":true,"managed":false,"uid":501,"item_url":"file:///Users/x/Library/LaunchAgents/com.vendor.updater.plist","app_url":""},"executable_path":"/Applications/Vendor.app/Contents/MacOS/updater","instigator_token":null,"app_token":null}`),
		esSystemLine("btm_launch_item_remove", btmd,
			`{"instigator":null,"app":null,"item":{"item_type":4,"legacy":false,"managed":false,"uid":0,"item_url":"file:///Applications/Secure%20Agent.app/Contents/Library/LaunchDaemons/com.cavi-ai.secure-agent-esd.plist","app_url":"file:///Applications/Secure%20Agent.app/"},"instigator_token":{"pid":500},"app_token":null}`),
		esSystemLine("profile_add", esProcessJSON(302, 1, "/usr/libexec/mdmclient"),
			`{"instigator":`+agent+`,"is_update":false,"profile":{"identifier":"com.example.proxy","uuid":"5D4C1E2A-0000-4000-8000-000000000001","install_source":1,"organization":"Example","display_name":"Example Proxy","scope":"User"},"instigator_token":{"pid":500}}`),
		esSystemLine("gatekeeper_user_override", agent,
			`{"file_type":0,"file":{"file_path":"/Users/x/Downloads/tool"},"sha256":null,"signing_info":null}`),
		esSystemLine("xp_malware_detected", xprotect,
			`{"signature_version":"5321","malware_identifier":"MACOS.ADLOAD.A","incident_identifier":"8C1F","detected_path":"/Users/x/Downloads/installer.app","detected_executable":"/Users/x/Downloads/installer.app/Contents/MacOS/installer"}`),
	}

	got := spoolFlags(t, lines, 5)
	wantFlags := []string{
		"launch-item-change|pid=500|agent=cursor|/Applications/Secure Agent.app/Contents/Library/LaunchDaemons/com.cavi-ai.secure-agent-esd.plist",
		"launch-item-change|pid=500|agent=cursor|/Users/x/Library/LaunchAgents/com.example.helper.plist",
		"trust-change|pid=500|agent=cursor|/Users/x/Downloads/tool",
		"trust-change|pid=500|agent=cursor|com.example.proxy",
		"xprotect-detection|pid=0|agent=xprotect|/Users/x/Downloads/installer.app",
	}
	if fmt.Sprint(got) != fmt.Sprint(wantFlags) {
		t.Fatalf("stored flags:\n got  %q\n want %q", got, wantFlags)
	}
}

// Background Task Management names smd as the instigator of a plist dropped
// into a LaunchAgents directory, and reports its removal a minute or more
// after the file is gone. The item is the agent's when the agent created,
// moved or deleted that file: the helper keeps those file events and the BTM
// event flags the agent. An item no agent wrote does not flag.
func TestSpoolLaunchItemFileWriterRaisesFlag(t *testing.T) {
	btmd := esProcessJSON(583, 1, "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd")
	smd := esProcessJSON(379, 1, "/usr/libexec/smd")
	agent := esProcessJSON(500, 1, "/usr/local/bin/cursor-agent")
	btmAdd := func(plist string) string {
		return esSystemLine("btm_launch_item_add", btmd,
			`{"instigator":`+smd+`,"app":null,"item":{"uid":501,"item_url":"file:///Users/x/Library/LaunchAgents/`+plist+`","app_url":null,"item_type":3,"legacy":true,"managed":false},"executable_path":"/usr/bin/true","instigator_token":{"pid":379},"app_token":null}`)
	}
	lines := []string{
		esSystemLine("create", agent,
			`{"destination_type":1,"destination":{"new_path":{"dir":{"path":"/Users/x/Library/LaunchAgents","path_truncated":false},"filename":"com.example.probe.plist"}},"acl":null}`),
		btmAdd("com.example.probe.plist"),
		esSystemLine("rename", agent,
			`{"source":{"path":"/Users/x/project/moved.plist","path_truncated":false},"destination_type":1,"destination":{"new_path":{"dir":{"path":"/Users/x/Library/LaunchAgents","path_truncated":false},"filename":"com.example.moved.plist"}}}`),
		btmAdd("com.example.moved.plist"),
		esSystemLine("unlink", agent,
			`{"target":{"path":"/Users/x/Library/LaunchAgents/com.example.probe.plist","path_truncated":false},"parent_dir":{"path":"/Users/x/Library/LaunchAgents"}}`),
		esSystemLineAt("2026-10-28T21:01:10.000000000Z", "btm_launch_item_remove", btmd,
			`{"instigator":`+smd+`,"app":null,"item":{"uid":501,"item_url":"file:///Users/x/Library/LaunchAgents/com.example.probe.plist","app_url":null,"item_type":3,"legacy":true,"managed":false},"instigator_token":{"pid":379},"app_token":null}`),
		btmAdd("com.vendor.updater.plist"),
	}
	var kept []string
	for _, l := range lines {
		if l = esEscapeSlashes(l); keepESLine([]byte(l)) {
			kept = append(kept, l)
		}
	}
	if len(kept) != len(lines) {
		t.Fatalf("helper kept %d of %d lines", len(kept), len(lines))
	}

	got := spoolFlags(t, kept, 3)
	wantFlags := []string{
		"launch-item-change|pid=500|agent=cursor|/Users/x/Library/LaunchAgents/com.example.moved.plist",
		"launch-item-change|pid=500|agent=cursor|/Users/x/Library/LaunchAgents/com.example.probe.plist",
		"launch-item-change|pid=500|agent=cursor|/Users/x/Library/LaunchAgents/com.example.probe.plist",
	}
	if fmt.Sprint(got) != fmt.Sprint(wantFlags) {
		t.Fatalf("stored flags:\n got  %q\n want %q", got, wantFlags)
	}
}

// esProfileXML is a configuration profile file's property list.
func esProfileXML(identifier, name string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array/>
	<key>PayloadDisplayName</key>
	<string>` + name + `</string>
	<key>PayloadIdentifier</key>
	<string>` + identifier + `</string>
	<key>PayloadType</key>
	<string>Configuration</string>
</dict>
</plist>
`
}

// esFileCreate is an eslogger create event body for name in dir.
func esFileCreate(dir, name string) string {
	return `{"destination_type":1,"destination":{"new_path":{"dir":{"path":"` + dir + `","path_truncated":false},"filename":"` + name + `"}},"acl":null}`
}

// macOS names syspolicyd for the user's Gatekeeper override and System
// Settings for the user's profile install. The change is the agent's when the
// agent wrote the overridden app bundle, or the profile file holding the
// installed identifier, within the day before: the helper keeps those file
// events and the override or install flags the agent. Changes no agent staged,
// and an app the agent wrote more than a day before, do not flag.
func TestSpoolTrustChangeFileWriterRaisesFlag(t *testing.T) {
	dir := t.TempDir()
	for name, id := range map[string]string{"probe.mobileconfig": "com.example.probe", "other.mobileconfig": "com.example.other"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(esProfileXML(id, "Example")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	syspolicyd := esProcessJSON(567, 1, "/usr/libexec/syspolicyd")
	mdmclient := esProcessJSON(302, 1, "/usr/libexec/mdmclient")
	settings := esProcessJSON(610, 1, "/System/Applications/System Settings.app/Contents/MacOS/System Settings")
	agent := esProcessJSON(500, 1, "/usr/local/bin/cursor-agent")
	override := func(at, app string) string {
		return esSystemLineAt(at, "gatekeeper_user_override", syspolicyd,
			`{"file":{"path":"`+app+`","path_truncated":false,"stat":{"st_mode":16877}},"signing_info":null,"sha256":"NULL","file_type":1}`)
	}
	install := func(at, id string) string {
		return esSystemLineAt(at, "profile_add", mdmclient,
			`{"instigator":`+settings+`,"is_update":false,"profile":{"identifier":"`+id+`","uuid":"5D4C1E2A-0000-4000-8000-000000000002","install_source":1,"organization":"","display_name":"Example","scope":"User"},"instigator_token":{"pid":610}}`)
	}
	lines := []string{
		esSystemLineAt("2026-10-27T20:00:00.000000000Z", "create", agent, esFileCreate("/Users/x/Downloads", "Old.app")),
		esSystemLine("create", agent, esFileCreate("/Users/x/Downloads", "Probe.app")),
		esSystemLine("create", agent, esFileCreate(dir, "probe.mobileconfig")),
		esSystemLine("create", agent, esFileCreate(dir, "other.mobileconfig")),
		override("2026-10-28T23:30:00.000000000Z", "/Users/x/Downloads/Old.app"),
		override("2026-10-28T23:30:01.000000000Z", "/Users/x/Downloads/Vendor.app"),
		install("2026-10-28T23:30:02.000000000Z", "com.vendor.mdm"),
		override("2026-10-28T23:30:03.000000000Z", "/Users/x/Downloads/Probe.app"),
		install("2026-10-28T23:30:04.000000000Z", "com.example.probe"),
	}
	var kept []string
	for _, l := range lines {
		if l = esEscapeSlashes(l); keepESLine([]byte(l)) {
			kept = append(kept, l)
		}
	}
	if len(kept) != len(lines) {
		t.Fatalf("helper kept %d of %d lines", len(kept), len(lines))
	}

	got := spoolFlags(t, kept, 2)
	wantFlags := []string{
		"trust-change|pid=500|agent=cursor|/Users/x/Downloads/Probe.app",
		"trust-change|pid=500|agent=cursor|com.example.probe",
	}
	if fmt.Sprint(got) != fmt.Sprint(wantFlags) {
		t.Fatalf("stored flags:\n got  %q\n want %q", got, wantFlags)
	}
}

// mdmclient reads a profile file when it is opened for install; an agent that
// deletes the file afterwards is still named when the user installs it.
func TestTrustChangeProfileFileDeletedAfterInstallRead(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "staged.mobileconfig")
	if err := os.WriteFile(profile, []byte(esProfileXML("com.example.staged", "Staged")), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load("/nonexistent")
	tg := agents.New(cfg, fakeProcSource{})
	tg.Refresh()
	cr := correlate.New(tg, sensitive.New(cfg), cfg, correlate.Hooks{})
	observe := func(line string) []model.Flag {
		t.Helper()
		e, ok := collect.ParseESLine([]byte(line))
		if !ok {
			t.Fatalf("unparsed line %s", line)
		}
		return cr.Observe(e)
	}
	mdmclient := esProcessJSON(302, 1, "/usr/libexec/mdmclient")
	settings := esProcessJSON(610, 1, "/System/Applications/System Settings.app/Contents/MacOS/System Settings")
	observe(esSystemLine("create", esProcessJSON(500, 1, "/usr/local/bin/cursor-agent"), esFileCreate(dir, "staged.mobileconfig")))
	observe(esSystemLine("open", mdmclient, `{"fflag":1,"file":{"path":"`+profile+`","path_truncated":false}}`))
	if err := os.Remove(profile); err != nil {
		t.Fatal(err)
	}
	flags := observe(esSystemLineAt("2026-10-28T22:00:00.000000000Z", "profile_add", mdmclient,
		`{"instigator":`+settings+`,"is_update":false,"profile":{"identifier":"com.example.staged","uuid":"5D4C1E2A-0000-4000-8000-000000000003","install_source":1,"organization":"","display_name":"Staged","scope":"User"},"instigator_token":{"pid":610}}`))
	if len(flags) != 1 || flags[0].Rule != "trust-change" || flags[0].Agent != "cursor" || flags[0].PID != 500 ||
		flags[0].Evidence[0].Label != "com.example.staged" || !strings.Contains(flags[0].Evidence[0].Text, profile) {
		t.Fatalf("flags = %+v, want one trust-change for cursor pid 500 naming com.example.staged from %s", flags, profile)
	}
}

// spoolFlags writes lines to a spool, runs the spool tailer, bus, correlator
// and store over it, and returns the stored flags as sorted
// "rule|pid=N|agent=A|label" strings once want of them exist or 5 s pass.
func spoolFlags(t *testing.T, lines []string, want int) []string {
	t.Helper()
	dir := t.TempDir()
	spool := filepath.Join(dir, "es-spool.jsonl")
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(spool, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg, _ := config.Load("/nonexistent")
	tg := agents.New(cfg, fakeProcSource{})
	tg.Refresh()
	cr := correlate.New(tg, sensitive.New(cfg), cfg, correlate.Hooks{})

	b := bus.New(64)
	sub := b.Subscribe()
	done := make(chan struct{})
	go func() {
		for e := range sub {
			st.PutEvent(e)
			for _, fl := range cr.Observe(e) {
				st.PutFlag(fl)
			}
		}
		close(done)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	tailer := collect.NewSpoolTailerAt(b, spool)
	go func() { _ = tailer.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		b.Close()
		<-done
	})

	var flags []model.Flag
	deadline := time.Now().Add(5 * time.Second)
	for {
		flags = testutil.Read[[]model.Flag](t)(st.QueryFlags(store.FlagFilter{Limit: 20}))
		if len(flags) >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := make([]string, 0, len(flags))
	for _, fl := range flags {
		label := ""
		if len(fl.Evidence) > 0 {
			label = fl.Evidence[0].Label
		}
		got = append(got, fmt.Sprintf("%s|pid=%d|agent=%s|%s", fl.Rule, fl.PID, fl.Agent, label))
	}
	sort.Strings(got)
	return got
}
