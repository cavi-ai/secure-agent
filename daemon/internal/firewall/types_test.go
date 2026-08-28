package firewall

import "testing"

func TestModeAndActionZeroValues(t *testing.T) {
	// Monitor and Allow must be the zero values so a mis-wired default is safe.
	if ModeMonitor != 0 {
		t.Fatalf("ModeMonitor must be zero value, got %d", ModeMonitor)
	}
	if ActionAllow != 0 {
		t.Fatalf("ActionAllow must be zero value, got %d", ActionAllow)
	}
	if VerdictLegit != 0 {
		t.Fatalf("VerdictLegit must be zero value, got %d", VerdictLegit)
	}
}

func TestParseMode(t *testing.T) {
	if ParseMode("block") != ModeBlock {
		t.Fatal("block should parse to ModeBlock")
	}
	if ParseMode("") != ModeMonitor || ParseMode("garbage") != ModeMonitor {
		t.Fatal("unknown/empty mode must default to ModeMonitor (fail-safe)")
	}
}
