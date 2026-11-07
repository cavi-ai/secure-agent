package collect

import (
	"strings"
	"testing"
	"time"
)

func TestCodexSightingUsesRecordedTimeAndCurrentWorkspace(t *testing.T) {
	var tracers jsonlTracers
	path := "/home/codex/sessions/rollout-session.jsonl"
	meta := `{"timestamp":"2026-10-01T10:00:00Z","type":"session_meta","payload":{"session_id":"s","cwd":"/"}}`
	r := tracers.Parse(path, meta, 0, strings.NewReader(meta))
	want, _ := time.Parse(time.RFC3339, "2026-10-01T10:00:00Z")
	if !r.Session.At.Equal(want) {
		t.Errorf("replayed metadata sighted at %v, want recorded time %v", r.Session.At, want)
	}
	context := `{"timestamp":"2026-10-02T10:00:00Z","type":"turn_context","payload":{"cwd":"/workspace/project","model":"local"}}`
	r = tracers.Parse(path, context, 0, strings.NewReader(""))
	want, _ = time.Parse(time.RFC3339, "2026-10-02T10:00:00Z")
	if !r.Parsed || r.Session.Workspace != "/workspace/project" || !r.Session.At.Equal(want) {
		t.Fatalf("workspace update not published: %+v", r)
	}
	r = tracers.Parse(path, codexTokenLine, 0, strings.NewReader(""))
	if r.Session.Workspace != "/workspace/project" {
		t.Fatalf("later activity lost current workspace: %+v", r.Session)
	}
}
