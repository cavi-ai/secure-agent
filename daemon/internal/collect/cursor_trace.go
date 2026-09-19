package collect

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Cursor agent-transcript trace parsing
// (~/.cursor/projects/<slug>/agent-transcripts/<uuid>/<uuid>.jsonl).
//
// Cursor writes one JSONL file per agent run. Each line is a role record with
// a message.content array carrying text and tool_use blocks. Two deliberate
// limits, because the format has them:
//   - No timestamps: events use the observation time (file append time).
//   - No tool_result: a tool_use is never paired with its result, so a call
//     is emitted with status "running" and no duration. The tool NAME and the
//     turn structure are the trace; durations for Cursor cannot be recovered.
//
// No model id, token counts, or cost appear in these transcripts either, so
// Cursor sessions carry tool calls and turns only. Content is never carried
// into events — only tool names.
//
// The session id is the file's own UUID (the directory and file share it);
// the workspace is derived best-effort from the project slug.

// cursorRecord is the subset of the Cursor transcript schema the tracer reads.
type cursorRecord struct {
	Role    string `json:"role"` // user | assistant
	Message struct {
		Content []json.RawMessage `json:"content"`
	} `json:"message"`
}

type cursorContent struct {
	Type string `json:"type"` // text | tool_use
	Name string `json:"name"` // tool_use: tool name
	Text string `json:"text"` // text blocks
}

// CursorTracer turns Cursor transcript lines into trace events. Stateless
// beyond the per-file session id: Cursor has no pairing or usage to track.
type CursorTracer struct {
	sessionID string
	workspace string
}

// NewCursorTracer builds a tracer for one transcript file, taking the session
// id from the filename (<uuid>.jsonl) and the workspace from the project slug.
func NewCursorTracer(path string) *CursorTracer {
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	t := &CursorTracer{sessionID: base}
	// .../projects/<slug>/agent-transcripts/<uuid>/<uuid>.jsonl → slug.
	if parts := strings.Split(filepath.ToSlash(path), "/projects/"); len(parts) == 2 {
		slug := strings.SplitN(parts[1], "/", 2)[0]
		t.workspace = workspaceFromCursorSlug(slug)
	}
	return t
}

// workspaceFromCursorSlug best-effort decodes Cursor's lossy project slug
// ("Volumes-Work-hermes" → "/Volumes/Work/hermes"). Dashes inside real path
// components are indistinguishable from separators, so this is only trusted
// when the slug starts at a known root; otherwise it is left empty rather
// than guessed into a wrong path.
func workspaceFromCursorSlug(slug string) string {
	for _, root := range []string{"Volumes-", "Users-", "home-", "private-", "tmp-"} {
		if strings.HasPrefix(slug, root) {
			return "/" + strings.ReplaceAll(slug, "-", "/")
		}
	}
	return ""
}

// Session returns the identity learned from the filename.
func (t *CursorTracer) Session() (id, workspace string) { return t.sessionID, t.workspace }

// IsCursorTranscriptPath reports whether a tailed file is a Cursor agent
// transcript (project agent-transcripts), not one of Cursor's other logs.
func IsCursorTranscriptPath(path string) bool {
	return strings.Contains(path, "/.cursor/projects/") &&
		strings.Contains(path, "/agent-transcripts/") &&
		strings.HasSuffix(path, ".jsonl")
}

// ParseLine consumes one transcript line and returns zero or more trace
// events. ok=false means the line is not a Cursor role record.
func (t *CursorTracer) ParseLine(line string) (events []event.Event, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, `"role"`) {
		return nil, false
	}
	var rec cursorRecord
	if err := json.Unmarshal([]byte(trimmed), &rec); err != nil {
		return nil, false
	}
	if rec.Role != "assistant" && rec.Role != "user" || t.sessionID == "" {
		return nil, false
	}
	var contents []cursorContent
	for _, raw := range rec.Message.Content {
		var c cursorContent
		if err := json.Unmarshal(raw, &c); err == nil {
			contents = append(contents, c)
		}
	}
	ts := time.Now() // Cursor transcripts carry no timestamps.

	switch rec.Role {
	case "assistant":
		for _, c := range contents {
			if c.Type == "tool_use" && c.Name != "" {
				events = append(events, event.Event{
					Kind: event.KindToolCall, TS: ts, SessionID: t.sessionID,
					ToolName: c.Name, ToolStatus: "running", // no result to pair with
				})
			}
		}
	case "user":
		// A user record with real text is a turn boundary. Cursor wraps the
		// prompt in <user_query> tags; that still counts as a turn.
		for _, c := range contents {
			if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
				events = append(events, event.Event{
					Kind: event.KindTurn, TS: ts, SessionID: t.sessionID,
				})
				break
			}
		}
	}
	return events, len(events) > 0
}
