package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	return fmt.Sprintf(`{"version":8,"time":"2026-10-28T21:00:00.000000000Z","event_type":0,"process":%s,"event":{%q:%s}}`, proc, name, body)
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

	const want = 5
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
