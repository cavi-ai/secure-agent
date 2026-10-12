package collect

import (
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// A record without a time of its own is stamped with the read time and
// marked observed; a record with one keeps it and is not marked.
func TestClockStampedEventsAreMarkedObserved(t *testing.T) {
	without := func(line, field string) string {
		start := strings.Index(line, `"`+field+`":"`)
		end := strings.Index(line[start+len(field)+4:], `"`) + start + len(field) + 4
		return line[:start] + line[end+2:]
	}
	handshake := `{"type":"session_start","session_id":"hook-session","harness":"cursor","workspace":"/repo","pid":42,"ts":"2026-10-06T18:00:00Z"}`
	plugin := `{"ts":"2026-10-06T18:00:00Z","tool":"Read","pid":1,"session_id":"s","file_path":"/repo/a"}`
	cases := []struct {
		name     string
		events   func() []event.Event
		observed bool
	}{
		{"claude", func() []event.Event { evs, _, _ := NewClaudeTracer().ParseLine(claudeAssistantLine); return evs }, false},
		{"claude without timestamp", func() []event.Event {
			evs, _, _ := NewClaudeTracer().ParseLine(without(claudeAssistantLine, "timestamp"))
			return evs
		}, true},
		{"codex", func() []event.Event {
			tr := NewCodexTracer("")
			tr.ParseLine(codexMetaLine)
			evs, _ := tr.ParseLine(codexCallLine)
			return evs
		}, false},
		{"codex without timestamp", func() []event.Event {
			tr := NewCodexTracer("")
			tr.ParseLine(codexMetaLine)
			evs, _ := tr.ParseLine(without(codexCallLine, "timestamp"))
			return evs
		}, true},
		{"antigravity", func() []event.Event { evs, _ := agyTestTracer().ParseLine(agyToolLine); return evs }, false},
		{"antigravity without created_at", func() []event.Event {
			evs, _ := agyTestTracer().ParseLine(without(agyToolLine, "created_at"))
			return evs
		}, true},
		{"cursor", func() []event.Event {
			evs, _ := NewCursorTracer("/Users/x/.cursor/projects/Users-x-repo/agent-transcripts/c-1/c-1.jsonl").
				ParseLine(`{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read"}]}}`)
			return evs
		}, true},
		{"plugin log", func() []event.Event { e, _ := parsePluginLine(plugin); return []event.Event{e} }, false},
		{"plugin log without ts", func() []event.Event { e, _ := parsePluginLine(without(plugin, "ts")); return []event.Event{e} }, true},
		{"handshake", func() []event.Event {
			return NewTranscriptScanner(nil, nil).eventsForLine("", handshake, 0, 0, nil)
		}, false},
		{"handshake with an unreadable ts", func() []event.Event {
			return NewTranscriptScanner(nil, nil).eventsForLine("", strings.Replace(handshake, "2026-10-06T18:00:00Z", "yesterday", 1), 0, 0, nil)
		}, true},
	}
	for _, c := range cases {
		evs := c.events()
		if len(evs) == 0 {
			t.Fatalf("%s: no events", c.name)
		}
		for _, e := range evs {
			if e.ObservedTS != c.observed || e.TS.IsZero() {
				t.Errorf("%s: %v event ObservedTS=%v TS=%v, want ObservedTS=%v", c.name, e.Kind, e.ObservedTS, e.TS, c.observed)
			}
		}
	}
}

func agyTestTracer() *AGYTracer {
	return NewAGYTracer("/Users/x/.gemini/antigravity-cli/brain/b285eea1-3969/.system_generated/logs/transcript_full.jsonl")
}

// lcm.db rows with an unreadable created_at are marked observed.
func TestOpenclawUnreadableTimeIsObserved(t *testing.T) {
	dir, db := openclawFixture(t)
	c, sub, _, _ := newTestOpenclaw(t, dir)
	for _, e := range drainOpenclaw(sub, c.pollOnce()) {
		if e.ObservedTS {
			t.Fatalf("event with a recorded time marked observed: %+v", e)
		}
	}
	if _, err := db.Exec(`INSERT INTO messages (message_id, conversation_id, seq, role, content, token_count, created_at)
		VALUES (7, 2, 2, 'user', 'x', 1, 'not a time')`); err != nil {
		t.Fatal(err)
	}
	evs := drainOpenclaw(sub, c.pollOnce())
	if len(evs) != 1 || !evs[0].ObservedTS {
		t.Fatalf("events for a row without a time = %+v, want one observed", evs)
	}
}

// Hermes usage of a session Hermes has not ended carries the read time and is
// marked observed; message rows keep their recorded time unless it is unset.
func TestHermesUsageOfALiveSessionIsObserved(t *testing.T) {
	root, main, _ := hermesFixture(t)
	c, sub, _, _ := newTestHermes(t, root)
	n := c.pollOnce()
	usage := 0
	for i := 0; i < n; i++ {
		e := <-sub
		live := e.Kind == event.KindModelCall && e.SessionID == "s-child"
		if live {
			usage++
		}
		if e.ObservedTS != live {
			t.Errorf("%v event of %s: ObservedTS=%v, want %v", e.Kind, e.SessionID, e.ObservedTS, live)
		}
	}
	if usage == 0 {
		t.Fatal("no usage events for the live session")
	}
	hermesExec(t, main, `INSERT INTO messages (id, session_id, role, content, timestamp, token_count) VALUES (6, 's-child', 'user', 'x', 0, 1)`)
	n = c.pollOnce()
	if n == 0 {
		t.Fatal("no events for a message without a timestamp")
	}
	for i := 0; i < n; i++ {
		if e := <-sub; !e.ObservedTS {
			t.Errorf("%v event for a message without a timestamp not marked observed", e.Kind)
		}
	}
}
