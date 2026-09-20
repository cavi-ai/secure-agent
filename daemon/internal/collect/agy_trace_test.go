package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

const agyToolLine = `{"step_index":3,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-09-11T09:38:12Z","tool_calls":[{"name":"run_command","args":{"CommandLine":"ls"}},{"name":"view_file","args":{"AbsolutePath":"/x/y"}}]}`
const agyRunningLine = `{"step_index":4,"source":"MODEL","type":"PLANNER_RESPONSE","status":"RUNNING","created_at":"2026-09-11T09:38:13Z","tool_calls":[{"name":"run_command","args":{"CommandLine":"sleep 10"}}]}`
const agyUserLine = `{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","created_at":"2026-09-11T09:38:10Z","content":"do the thing"}`

func TestAGYTraceToolsStatusAndTurn(t *testing.T) {
	tr := NewAGYTracer("/Users/x/.gemini/antigravity-cli/brain/b285eea1-3969/.system_generated/logs/transcript_full.jsonl")
	id, _ := tr.Session()
	if id != "b285eea1-3969" {
		t.Fatalf("session id = %q, want the brain uuid", id)
	}

	evs, ok := tr.ParseLine(agyToolLine)
	if !ok || len(evs) != 2 {
		t.Fatalf("tool line evs = %+v", evs)
	}
	for _, e := range evs {
		if e.Kind != event.KindToolCall || e.SessionID != "b285eea1-3969" {
			t.Fatalf("tool_call = %+v", e)
		}
		if e.ToolStatus != "ok" {
			t.Fatalf("DONE step status = %q, want ok", e.ToolStatus)
		}
	}
	if evs[0].ToolName != "run_command" || evs[1].ToolName != "view_file" {
		t.Fatalf("tool names = %q,%q", evs[0].ToolName, evs[1].ToolName)
	}

	// RUNNING step → running status; error via exit code.
	evs, _ = tr.ParseLine(agyRunningLine)
	if len(evs) != 1 || evs[0].ToolStatus != "running" {
		t.Fatalf("running step = %+v", evs)
	}
	if s := agyToolStatus("DONE", intPtr(1)); s != "error" {
		t.Fatalf("nonzero exit = %q, want error", s)
	}
	if s := agyToolStatus("DONE", intPtr(0)); s != "ok" {
		t.Fatalf("zero exit = %q, want ok", s)
	}

	// User input → a turn boundary.
	evs, ok = tr.ParseLine(agyUserLine)
	if !ok || len(evs) != 1 || evs[0].Kind != event.KindTurn {
		t.Fatalf("user evs = %+v", evs)
	}
}

func TestAGYPaths(t *testing.T) {
	full := "/Users/x/.gemini/antigravity-cli/brain/abc/.system_generated/logs/transcript_full.jsonl"
	if !IsAGYTranscriptPath(full) {
		t.Fatal("agy full transcript not recognized")
	}
	// The plain variant and chunk files are not traced (duplicate steps).
	if IsAGYTranscriptPath("/Users/x/.gemini/antigravity-cli/brain/abc/.system_generated/logs/transcript.jsonl") {
		t.Fatal("plain transcript variant must not be traced (duplicate)")
	}
	chunk := "/Users/x/.gemini/antigravity-cli/brain/abc/.system_generated/logs/chunks/transcript/00000000.jsonl"
	if !IsAGYChunkPath(chunk) {
		t.Fatal("agy chunk file not recognized")
	}
}

func intPtr(n int) *int { return &n }

// agy records carry no tool-call id; the tracer mints stable synthetic ids
// (session + per-file sequence) so rows are keyed and idempotent under
// transcript re-reads instead of one unpairable insert per replay.
func TestAGYToolCallsCarrySyntheticCallID(t *testing.T) {
	tr := NewAGYTracer("/Users/x/.gemini/antigravity-cli/brain/uuid-one/.system_generated/logs/transcript_full.jsonl")
	evs, _ := tr.ParseLine(agyToolLine)
	if len(evs) != 2 || evs[0].CallID == "" || evs[1].CallID == "" {
		t.Fatalf("call ids = %q,%q, want synthetic non-empty", evs[0].CallID, evs[1].CallID)
	}
	if evs[0].CallID == evs[1].CallID {
		t.Fatal("two calls in one step share an id")
	}
	// Deterministic across tracer rebuilds of the same file position: same
	// session + sequence → same id.
	tr2 := NewAGYTracer("/Users/x/.gemini/antigravity-cli/brain/uuid-one/.system_generated/logs/transcript_full.jsonl")
	evs2, _ := tr2.ParseLine(agyToolLine)
	if evs2[0].CallID != evs[0].CallID {
		t.Fatalf("rebuild id %q != original %q", evs2[0].CallID, evs[0].CallID)
	}
}

// The synthetic id sequence resumes past the calls already in the file after
// a daemon restart (the tailer resumes at EOF; a counter restarting at 1
// would upsert later calls onto pre-restart rows).
func TestAGYToolCallSequenceSurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "brain", "uuid-nine", ".system_generated", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "transcript_full.jsonl")
	pre := strings.Join([]string{
		`{"step_index":1,"type":"USER_INPUT","status":"DONE","created_at":"2026-09-11T09:38:10Z","content":"go"}`,
		`{"step_index":2,"type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-09-11T09:38:12Z","tool_calls":[{"name":"run_command"}]}`,
		"", // trailing newline, as a real transcript has
	}, "\n")
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := NewAGYTracer(path)
	evs, ok := tr.ParseLine(agyToolLine)
	if !ok || len(evs) != 2 {
		t.Fatalf("evs = %+v, want 2 tool calls", evs)
	}
	if want := "-agy-2"; !strings.HasSuffix(evs[0].CallID, want) {
		t.Fatalf("call id = %q, want suffix %q (resumes past the 1 pre-restart call)", evs[0].CallID, want)
	}
	if want := "-agy-3"; !strings.HasSuffix(evs[1].CallID, want) {
		t.Fatalf("call id = %q, want suffix %q", evs[1].CallID, want)
	}
}
