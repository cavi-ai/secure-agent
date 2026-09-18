package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The rotate subcommand POSTed to /rotate, an endpoint deleted in the security
// remediation. It must be gone from both dispatch and help text.
func TestUsageHasNoRotate(t *testing.T) {
	out, err := exec.Command("go", "run", ".", "help").CombinedOutput()
	if err != nil {
		t.Fatalf("run help: %v\n%s", err, out)
	}
	if strings.Contains(strings.ToLower(string(out)), "rotate") {
		t.Fatalf("usage still mentions rotate:\n%s", out)
	}
}

// The headless service plist must NOT use KeepAlive — the old launchd agent
// looped precisely because KeepAlive respawned the daemon against the menu
// bar app. RunAtLoad gives GUI-independent lifetime without the fight.
func TestServicePlistHasNoKeepAlive(t *testing.T) {
	plist := servicePlistXML("/Apps/secure-agentd", "/Users/x", "/Users/x/Library/Logs/secure-agent")
	if strings.Contains(plist, "<key>KeepAlive</key><true/>") {
		t.Fatal("service plist must not KeepAlive-respawn the daemon")
	}
	for _, want := range []string{
		"<key>RunAtLoad</key><true/>",
		"<string>/Apps/secure-agentd</string>",
		"<key>HOME</key><string>/Users/x</string>",
		"/Users/x/Library/Logs/secure-agent/secure-agentd.err.log",
		serviceLabel,
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
}

// The service label must differ from the menubar's legacy agent label so the
// two never collide in launchd bookkeeping.
func TestServiceLabelDistinctFromLegacy(t *testing.T) {
	if serviceLabel == "com.cavi-ai.secure-agentd" {
		t.Fatal("service label must not reuse the retired menubar agent label")
	}
	if !strings.HasPrefix(serviceLabel, "com.cavi-ai.secure-agent.") {
		t.Fatalf("service label %q should be namespaced under com.cavi-ai.secure-agent.", serviceLabel)
	}
}
