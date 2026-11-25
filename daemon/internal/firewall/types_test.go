package firewall

import "testing"

func TestParseMode(t *testing.T) {
	if ParseMode("block") != ModeBlock {
		t.Fatal("block should parse to ModeBlock")
	}
	if ParseMode("") != ModeMonitor || ParseMode("garbage") != ModeMonitor {
		t.Fatal("unknown/empty mode must default to ModeMonitor (fail-safe)")
	}
}
