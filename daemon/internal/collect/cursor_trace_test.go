package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

const cursorUserLine = `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nhow can i check the current remote\n</user_query>"}]}}`
const cursorAssistantLine = `{"role":"assistant","message":{"content":[{"type":"text","text":"Checking remotes."},{"type":"tool_use","name":"Shell","input":{"command":"git remote -v"}},{"type":"tool_use","name":"Glob","input":{"glob_pattern":"**/.gitignore"}}]}}`

func TestCursorTraceToolsAndTurns(t *testing.T) {
	tr := NewCursorTracer("/Users/x/.cursor/projects/Volumes-MIRZA-hermes/agent-transcripts/abc/abcdef12-3456.jsonl")
	id, ws := tr.Session()
	if id != "abcdef12-3456" {
		t.Fatalf("session id = %q, want the filename uuid", id)
	}
	if ws != "/Volumes/MIRZA/hermes" {
		t.Fatalf("workspace = %q, want the decoded slug", ws)
	}

	// Assistant record → one tool_call per tool_use; status unknown (no
	// tool_result in Cursor; "running" would be swept to error).
	evs, ok := tr.ParseLine(cursorAssistantLine)
	if !ok || len(evs) != 2 {
		t.Fatalf("assistant evs = %+v, want 2 tool calls", evs)
	}
	for _, e := range evs {
		if e.Kind != event.KindToolCall || e.ToolStatus != "unknown" || e.SessionID != "abcdef12-3456" {
			t.Fatalf("tool_call = %+v", e)
		}
	}
	if evs[0].ToolName != "Shell" || evs[1].ToolName != "Glob" {
		t.Fatalf("tool names = %q,%q", evs[0].ToolName, evs[1].ToolName)
	}
	// No usage in Cursor transcripts: no model_call is invented.
	for _, e := range evs {
		if e.Kind == event.KindModelCall {
			t.Fatal("Cursor has no usage; a model_call must not be fabricated")
		}
	}

	// User record with text → a turn boundary.
	evs, ok = tr.ParseLine(cursorUserLine)
	if !ok || len(evs) != 1 || evs[0].Kind != event.KindTurn {
		t.Fatalf("user evs = %+v, want one turn", evs)
	}
}

func TestCursorRejectsForeign(t *testing.T) {
	tr := NewCursorTracer("/tmp/x.jsonl")
	if _, ok := tr.ParseLine(`{"tool":"Read","pid":1}`); ok {
		t.Fatal("plugin activity line must not parse as a Cursor transcript")
	}
	if _, ok := tr.ParseLine(`{"role":"system","message":{"content":[]}}`); ok {
		t.Fatal("non user/assistant roles produce no trace")
	}
}

func TestIsCursorTranscriptPath(t *testing.T) {
	if !IsCursorTranscriptPath("/Users/x/.cursor/projects/slug/agent-transcripts/abc/abc.jsonl") {
		t.Fatal("cursor agent transcript not recognized")
	}
	if IsCursorTranscriptPath("/Users/x/.cursor/logs/foo.jsonl") {
		t.Fatal("legacy cursor log misclassified as an agent transcript")
	}
}

func TestWorkspaceFromCursorSlugOnlyTrustedRoots(t *testing.T) {
	if got := workspaceFromCursorSlug("Volumes-MIRZA-hermes"); got != "/Volumes/MIRZA/hermes" {
		t.Fatalf("slug decode = %q", got)
	}
	// A slug that does not start at a known root is left empty, never guessed.
	if got := workspaceFromCursorSlug("some-random-project"); got != "" {
		t.Fatalf("untrusted slug = %q, want empty", got)
	}
}

// Cursor records carry no tool-call id; synthetic ids (session + sequence)
// key the rows so re-reads upsert instead of inserting unpairable dupes.
func TestCursorToolCallsCarrySyntheticCallID(t *testing.T) {
	tr := NewCursorTracer("/Users/x/.cursor/projects/slug-x/agent-transcripts/abc/abc.jsonl")
	line := `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read"}]}}`
	evs, _ := tr.ParseLine(line)
	if len(evs) != 1 || evs[0].CallID == "" {
		t.Fatalf("call id = %+v, want synthetic non-empty", evs)
	}
	tr2 := NewCursorTracer("/Users/x/.cursor/projects/slug-x/agent-transcripts/abc/abc.jsonl")
	evs2, _ := tr2.ParseLine(line)
	if evs2[0].CallID != evs[0].CallID {
		t.Fatalf("rebuild id %q != original %q", evs2[0].CallID, evs[0].CallID)
	}
}

// The synthetic id sequence resumes past the calls already in the file after
// a daemon restart (the tailer resumes at EOF; a counter restarting at 1
// would upsert later calls onto pre-restart rows).
func TestCursorToolCallSequenceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-uuid.jsonl")
	pre := strings.Join([]string{
		`{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read"},{"type":"tool_use","name":"Edit"}]}}`,
		`{"role":"user","message":{"content":[{"type":"text","text":"next"}]}}`,
		"", // trailing newline, as a real transcript has
	}, "\n")
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := NewCursorTracer(path)
	line := `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Bash"}]}}`
	evs, ok := tr.ParseLine(line)
	if !ok || len(evs) != 1 {
		t.Fatalf("evs = %+v, want 1 tool call", evs)
	}
	if want := "session-uuid-cur-3"; evs[0].CallID != want {
		t.Fatalf("call id = %q, want %q (resumes past the 2 pre-restart calls)", evs[0].CallID, want)
	}
}
