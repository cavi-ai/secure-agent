package collect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Antigravity (agy) transcript trace parsing
// (~/.gemini/antigravity-cli/brain/<uuid>/.system_generated/logs/transcript_full.jsonl).
//
// agy writes one step-indexed JSONL per conversation. Each record carries a
// type, a status, a created_at, optional thinking/content text, and an
// optional tool_calls array. The session id is the brain directory UUID.
//
// Trace mapping, using only what the format actually carries:
//   - a record with tool_calls → one tool_call event per call (name only;
//     args are never carried), status derived from the record's own status
//     and exit_code (DONE+exit0 → ok, RUNNING → running, else error);
//   - a USER_INPUT record → a turn boundary;
//   - no model id, tokens or cost appear in these transcripts, so agy
//     sessions carry tool calls and turns only.
//
// The two generated log variants (transcript.jsonl and transcript_full.jsonl)
// hold the same steps; only transcript_full is traced, so a step is never
// emitted twice. The chunk files under logs/chunks are ignored entirely.

// agyRecord is the subset of the agy transcript schema the tracer reads.
type agyRecord struct {
	StepIndex int    `json:"step_index"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	ExitCode  *int   `json:"exit_code"`
	ToolCalls []struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	} `json:"tool_calls"`
	Content string `json:"content"`
}

// AGYTracer turns agy transcript lines into trace events.
type AGYTracer struct {
	sessionID string
	workspace string
	// toolSeq numbers the tool calls within this file so each gets a stable
	// synthetic call id: agy records carry no tool-call id, and NULL call ids
	// are distinct in the store's unique index, so id-less rows insert forever
	// without updating.
	toolSeq int
}

// NewAGYTracer builds a tracer for one brain transcript, taking the session id
// from the brain directory UUID and the workspace best-effort from agy's
// conversation cache. The tool-call sequence is seeded from the calls already
// in the file so ids resume past them after a daemon restart.
func NewAGYTracer(path string) *AGYTracer {
	t := &AGYTracer{toolSeq: countAGYToolCalls(path)}
	// .../brain/<uuid>/.system_generated/logs/transcript_full.jsonl → uuid.
	if parts := strings.Split(filepath.ToSlash(path), "/brain/"); len(parts) == 2 {
		t.sessionID = strings.SplitN(parts[1], "/", 2)[0]
	}
	if t.sessionID != "" {
		t.workspace = agyWorkspaceFor(t.sessionID)
	}
	return t
}

// countAGYToolCalls counts the tool calls already in the file, matching
// ParseLine's emission rule exactly (records with named tool_calls entries).
func countAGYToolCalls(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"type"`) {
			continue
		}
		var rec agyRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		for _, tc := range rec.ToolCalls {
			if tc.Name != "" {
				n++
			}
		}
	}
	return n
}

// Session returns the identity learned from the path + cache.
func (t *AGYTracer) Session() (id, workspace string) { return t.sessionID, t.workspace }

// IsAGYTranscriptPath reports whether a tailed file is an agy full transcript.
// Chunk files and the plain transcript variant are excluded to avoid triple
// reading the same steps.
func IsAGYTranscriptPath(path string) bool {
	p := filepath.ToSlash(path)
	return strings.Contains(p, "/.gemini/antigravity-cli/brain/") &&
		strings.HasSuffix(p, "/.system_generated/logs/transcript_full.jsonl")
}

// IsAGYChunkPath reports whether a file is an agy transcript chunk — the same
// steps split into pieces. The scanner skips these entirely so redaction does
// not re-scan duplicated content.
func IsAGYChunkPath(path string) bool {
	return strings.Contains(filepath.ToSlash(path), "/.gemini/antigravity-cli/brain/") &&
		strings.Contains(filepath.ToSlash(path), "/logs/chunks/") &&
		strings.HasSuffix(path, ".jsonl")
}

// ParseLine consumes one transcript line and returns zero or more trace
// events. ok=false means the line is not an agy step record.
func (t *AGYTracer) ParseLine(line string) (events []event.Event, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, `"type"`) {
		return nil, false
	}
	var rec agyRecord
	if err := json.Unmarshal([]byte(trimmed), &rec); err != nil || t.sessionID == "" {
		return nil, false
	}
	ts := time.Now()
	if rec.CreatedAt != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, rec.CreatedAt); err == nil {
			ts = parsed
		} else if parsed, err := time.Parse(time.RFC3339, rec.CreatedAt); err == nil {
			ts = parsed
		}
	}

	// A user input is a turn boundary.
	if rec.Type == "USER_INPUT" {
		return []event.Event{{Kind: event.KindTurn, TS: ts, SessionID: t.sessionID}}, true
	}

	for _, tc := range rec.ToolCalls {
		if tc.Name == "" {
			continue
		}
		// Synthetic call id: session + per-file sequence.
		t.toolSeq++
		events = append(events, event.Event{
			Kind: event.KindToolCall, TS: ts, SessionID: t.sessionID,
			CallID:   fmt.Sprintf("%s-agy-%d", t.sessionID, t.toolSeq),
			ToolName: tc.Name, ToolStatus: agyToolStatus(rec.Status, rec.ExitCode),
		})
	}
	return events, len(events) > 0
}

// agyToolStatus maps a step's status + exit code to the tool-call status.
func agyToolStatus(status string, exit *int) string {
	switch status {
	case "RUNNING":
		return "running"
	case "DONE":
		if exit != nil && *exit != 0 {
			return "error"
		}
		return "ok"
	case "ERROR", "FAILED":
		return "error"
	}
	return "ok"
}

// agyWorkspaceFor reads agy's conversation cache (workspace path → session id)
// and returns the workspace for a session, best-effort. Cached for the process
// so a per-file tracer construction does not re-read the file each time.
var (
	agyCacheOnce sync.Once
	agyCache     map[string]string // session id → workspace
)

func agyWorkspaceFor(sessionID string) string {
	agyCacheOnce.Do(func() {
		agyCache = map[string]string{}
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		data, err := os.ReadFile(filepath.Join(home, ".gemini", "antigravity-cli", "cache", "last_conversations.json"))
		if err != nil {
			return
		}
		var m map[string]string // workspace path → session id
		if json.Unmarshal(data, &m) != nil {
			return
		}
		for ws, sid := range m {
			agyCache[sid] = ws
		}
	})
	return agyCache[sessionID]
}
