package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestTranscriptGenerationReset(t *testing.T) {
	for _, mode := range []string{"truncate", "replace", "restart", "rewrite", "rewrite-restart"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".claude", "projects", "repo", "session.jsonl")
			line := func(session string) string {
				return fmt.Sprintf(`{"sessionId":%q,"type":"assistant","message":{"id":"same","model":"model","usage":{"input_tokens":1,"output_tokens":1}}}`, session)
			}
			old, fresh := line("old"), line("new")
			if mode == "truncate" {
				old += strings.Repeat(" ", 2000)
			}
			writeTranscriptSource(t, path, old)
			b := bus.New(16)
			defer b.Close()
			sub := b.Subscribe()
			ts := NewTranscriptScanner(b, nil)
			ts.OffsetStatePath = filepath.Join(t.TempDir(), "offsets.json")
			offsets := map[string]int64{}
			ts.tailFile(path, offsets, nil)
			select {
			case <-sub:
			default:
				t.Fatal("initial call missing")
			}
			if err := ts.saveOffsets(offsets); err != nil {
				t.Fatal(err)
			}
			if mode == "truncate" || mode == "rewrite" || mode == "rewrite-restart" {
				writeTranscriptSource(t, path, fresh)
			} else {
				writeTranscriptSource(t, path+".new", fresh)
				if err := os.Rename(path+".new", path); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "restart" || mode == "rewrite-restart" {
				state := ts.OffsetStatePath
				ts = NewTranscriptScanner(b, nil)
				ts.OffsetStatePath = state
				offsets = ts.loadOffsets()
			}
			ts.tailFile(path, offsets, nil)
			select {
			case e := <-sub:
				if e.SessionID != "new" || e.CallID != "same" {
					t.Fatalf("new generation: %+v", e)
				}
			default:
				t.Fatal("new generation call skipped")
			}
			ts.tailFile(path, offsets, nil)
			select {
			case e := <-sub:
				t.Fatalf("duplicate: %+v", e)
			default:
			}
		})
	}
}

func TestSourceReplacementPreservesPendingDelivery(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "projects", "repo", "session.jsonl")
	line := func(session string) string {
		return fmt.Sprintf(`{"sessionId":%q,"type":"assistant","message":{"id":"same","model":"model","usage":{"input_tokens":1,"output_tokens":1}}}`, session)
	}
	writeTranscriptSource(t, path, line("old"))
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	b.TryPublish(event.Event{Kind: event.KindTurn})
	ts := NewTranscriptScanner(b, nil)
	offsets := map[string]int64{}
	ts.tailFile(path, offsets, nil)
	if ts.pending[path] == nil {
		t.Fatal("backpressure fixture did not stage old event")
	}
	writeTranscriptSource(t, path+".new", line("new"))
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	ts.tailFile(path, offsets, nil) // old event still blocked
	<-sub                           // filler
	for _, session := range []string{"old", "new"} {
		ts.tailFile(path, offsets, nil)
		select {
		case e := <-sub:
			if e.SessionID != session {
				t.Fatalf("delivery order: %+v want %s", e, session)
			}
		default:
			t.Fatalf("lost %s generation event", session)
		}
	}
	ts.tailFile(path, offsets, nil)
	select {
	case e := <-sub:
		t.Fatalf("duplicate generation event: %+v", e)
	default:
	}
}

func TestLegacyOffsetCheckpointResumesUnreadBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.jsonl")
	writeTranscriptSource(t, path, "old\nnew")
	b := bus.New(4)
	defer b.Close()
	ts := NewTranscriptScanner(b, nil)
	ts.OffsetStatePath = filepath.Join(t.TempDir(), "offsets.json")
	if err := os.WriteFile(ts.OffsetStatePath, []byte(fmt.Sprintf(`{%q:4}`, path)), 0600); err != nil {
		t.Fatal(err)
	}
	offsets := ts.loadOffsets()
	if offsets[path] != 4 {
		t.Fatalf("legacy checkpoint discarded: %v", offsets)
	}
	ts.tailFile(path, offsets, nil)
	if offsets[path] != 8 {
		t.Fatalf("legacy unread bytes skipped: %v", offsets)
	}
	if err := ts.saveOffsets(offsets); err != nil {
		t.Fatal(err)
	}
	if resumed := ts.loadOffsets(); resumed[path] != 8 || ts.sources[path].Prefix == "" {
		t.Fatalf("legacy migration: %v %v", resumed, ts.sources)
	}
}

func TestDeletedSourceIdentityRetiresAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.jsonl")
	writeTranscriptSource(t, path, "line")
	b := bus.New(4)
	defer b.Close()
	ts := NewTranscriptScanner(b, nil)
	ts.OffsetStatePath = filepath.Join(t.TempDir(), "offsets.json")
	offsets := map[string]int64{}
	ts.tailFile(path, offsets, nil)
	if err := ts.saveOffsets(offsets); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	restarted := NewTranscriptScanner(b, nil)
	restarted.OffsetStatePath = ts.OffsetStatePath
	if got := restarted.loadOffsets(); len(got) != 0 || len(restarted.sources) != 0 {
		t.Fatalf("deleted source retained: %v %v", got, restarted.sources)
	}
}

func TestPendingToolsBoundedAndLateCompletionRetained(t *testing.T) {
	cl, cx := NewClaudeTracer(), NewCodexTracer("")
	cx.ParseLine(codexMetaLine)
	for i := 0; i < 4096; i++ {
		cl.ParseLine(fmt.Sprintf(`{"timestamp":"2026-01-01T00:00:00Z","sessionId":"audit","type":"assistant","message":{"content":[{"type":"tool_use","id":"c-%d","name":"Read"}]}}`, i))
		cx.ParseLine(fmt.Sprintf(`{"timestamp":"2026-01-01T00:00:00Z","type":"response_item","payload":{"type":"function_call","call_id":"x-%d","name":"read"}}`, i))
	}
	if len(cl.pending.byID) > pendingToolLimit || len(cx.pending.byID) > pendingToolLimit {
		t.Fatal("unfinished calls exceeded memory budget")
	}
	for _, id := range []int{0, 4095} {
		ce, _, _ := cl.ParseLine(fmt.Sprintf(`{"timestamp":"2026-01-01T00:00:02Z","sessionId":"audit","type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"c-%d","is_error":true}]}}`, id))
		xe, _ := cx.ParseLine(fmt.Sprintf(`{"timestamp":"2026-01-01T00:00:02Z","type":"response_item","payload":{"type":"function_call_output","call_id":"x-%d"}}`, id))
		if len(ce) != 1 || len(xe) != 1 {
			t.Fatalf("completion lost: %v %v", ce, xe)
		}
		for _, e := range append(ce, xe...) {
			if id == 0 && (e.Detail == "" || e.DurationMs != 0) {
				t.Fatalf("evicted start fabricated timing: %+v", e)
			}
			if id == 4095 && (e.DurationMs != 2000 || e.ToolName == "") {
				t.Fatalf("recent duration lost: %+v", e)
			}
		}
		if ce[0].ToolStatus != "error" || xe[0].ToolStatus != "ok" {
			t.Fatal("completion status lost")
		}
	}
	cl.ParseLine(`{"sessionId":"other","type":"assistant","message":{"content":[]}}`)
	cx.ParseLine(`{"type":"session_meta","payload":{"session_id":"other"}}`)
	ce, _, _ := cl.ParseLine(`{"sessionId":"other","type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"c-4094"}]}}`)
	xe, _ := cx.ParseLine(`{"type":"response_item","payload":{"type":"function_call_output","call_id":"x-4094"}}`)
	if len(ce) != 0 || len(xe) != 0 {
		t.Fatal("tool state crossed session boundary")
	}
}
