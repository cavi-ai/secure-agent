package collect

import (
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestScanLineTranscriptHit(t *testing.T) {
	line := "some log output with Bearer sk-secrettoken123 in it"
	e, ok := ScanLine(line)
	if !ok || e.Kind != event.KindTranscriptHit {
		t.Fatalf("ScanLine kind = %v, ok = %v; want KindTranscriptHit, true", e.Kind, ok)
	}
	if e.Detail != "bearer-token" {
		t.Fatalf("Detail = %q, want bearer-token", e.Detail)
	}
	if strings.Contains(e.Detail, "sk-secrettoken123") {
		t.Fatal("secret token leaked into event detail!")
	}
}

func TestScanLinePluginAction(t *testing.T) {
	line := `{"ts":"2026-08-12T19:55:00Z","tool":"Bash","command":"ls"}`
	e, ok := ScanLine(line)
	if !ok || e.Kind != event.KindPluginAction {
		t.Fatalf("ScanLine kind = %v, ok = %v; want KindPluginAction, true", e.Kind, ok)
	}
	if e.Detail != "Bash" {
		t.Fatalf("Detail = %q, want Bash", e.Detail)
	}
}

func TestScanLineFakeCursorActivity(t *testing.T) {
	line := `{"file_path":"/tmp/foo/.env","pid":12345,"tool":"Read"}`
	e, ok := ScanLine(line)
	if !ok || e.Kind != event.KindPluginAction {
		t.Fatalf("ScanLine kind = %v, ok = %v; want KindPluginAction, true", e.Kind, ok)
	}
	if e.PID != 12345 {
		t.Fatalf("PID = %d, want 12345", e.PID)
	}
	if e.Path != "/tmp/foo/.env" {
		t.Fatalf("Path = %q, want /tmp/foo/.env", e.Path)
	}
}
