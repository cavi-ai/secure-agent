package collect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// A cancelled run still performs its initial discovery and final checkpoint.
// This exercises retirement in the production resolve path without tick races.
func resolveTranscriptState(t *testing.T, ts *TranscriptScanner) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ts.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
}

func writeTranscriptSource(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendTranscriptEvents(t *testing.T, ts *TranscriptScanner, sub <-chan event.Event, offsets map[string]int64, path, line string) []event.Event {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(line + "\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("append: %v, close: %v", err, closeErr)
	}
	ts.tailFile(path, offsets, nil)
	var events []event.Event
	for {
		select {
		case e := <-sub:
			events = append(events, e)
		default:
			return events
		}
	}
}

func TestTranscriptRetiresDeletedParserState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	b := bus.New(8)
	defer b.Close()
	ts := NewTranscriptScanner(b, nil)
	ts.OffsetStatePath = filepath.Join(home, "offsets.json")
	offsets := map[string]int64{}
	const count = 64
	for i := range count {
		for _, source := range []struct{ path, line string }{
			{filepath.Join(home, ".claude", "projects", "repo", fmt.Sprintf("c-%d.jsonl", i)), `{"sessionId":"claude","type":"user","message":{"content":"hello"}}`},
			{filepath.Join(home, "sessions", fmt.Sprintf("rollout-%d.jsonl", i)), codexMetaLine},
			{filepath.Join(home, ".cursor", "projects", "repo", "agent-transcripts", fmt.Sprintf("u-%d.jsonl", i)), `{"role":"user","message":{"content":[{"type":"text","text":"hello"}]}}`},
			{filepath.Join(home, ".gemini", "antigravity-cli", "brain", fmt.Sprintf("a-%d", i), ".system_generated", "logs", "transcript_full.jsonl"), `{"type":"USER_INPUT"}`},
		} {
			writeTranscriptSource(t, source.path, source.line)
			ts.tailFile(source.path, offsets, nil)
		}
	}
	if len(ts.tracers) != count || len(ts.codexTracers) != count || len(ts.cursorTracers) != count || len(ts.agyTracers) != count || len(ts.rolloutIDs) != count {
		t.Fatal("fixtures did not create each harness's parser and identity state")
	}
	if err := ts.saveOffsets(offsets); err != nil {
		t.Fatal(err)
	}
	// Delete after Run loads its checkpoints, before its discovery pass.
	ts.ExtraTargets = func() []string {
		for path := range offsets {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	resolveTranscriptState(t, ts)
	if len(ts.tracers)+len(ts.codexTracers)+len(ts.cursorTracers)+len(ts.agyTracers)+len(ts.rolloutIDs) != 0 {
		t.Fatalf("deleted sources retained state: claude=%d codex=%d cursor=%d agy=%d identities=%d", len(ts.tracers), len(ts.codexTracers), len(ts.cursorTracers), len(ts.agyTracers), len(ts.rolloutIDs))
	}
	if remaining := ts.loadOffsets(); len(remaining) != 0 {
		t.Fatalf("deleted checkpoints retained: %v", remaining)
	}
}

func TestTranscriptRetainsInactiveParserAndCheckpoint(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "sessions", "rollout-id.jsonl")
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil) // source is absent from discovery, still on disk
	ts.OffsetStatePath = filepath.Join(home, "offsets.json")
	offsets := map[string]int64{}
	appendTranscriptEvents(t, ts, sub, offsets, path, codexMetaLine)
	appendTranscriptEvents(t, ts, sub, offsets, path, codexSettingsLine)
	tracer, checkpoint := ts.codexTracers[path], offsets[path]
	if err := ts.saveOffsets(offsets); err != nil {
		t.Fatal(err)
	}
	resolveTranscriptState(t, ts)
	if ts.codexTracers[path] != tracer || ts.loadOffsets()[path] != checkpoint || ts.RolloutSession(path) != "019f58e8-6230" {
		t.Fatal("inactive but present source lost parser, checkpoint or identity")
	}
	events := appendTranscriptEvents(t, ts, sub, offsets, path, codexTokenLine)
	if len(events) != 1 || events[0].Kind != event.KindModelCall || events[0].SessionID != "019f58e8-6230" || events[0].Model != "m-test" {
		t.Fatalf("reactivated source lost attribution or replayed history: %+v", events)
	}
}

func TestTranscriptRetiresDeletedSourceAfterPendingDelivery(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "projects", "repo", "session.jsonl")
	line := `{"sessionId":"pending-session","type":"assistant","message":{"id":"msg","model":"m-test","usage":{"input_tokens":1,"output_tokens":1},"content":[{"type":"tool_use","id":"tool","name":"Read"}]}}`
	writeTranscriptSource(t, path, line)
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.OffsetStatePath = filepath.Join(home, "offsets.json")
	offsets := map[string]int64{}
	ts.tailFile(path, offsets, nil)
	tracer := ts.tracers[path]
	if ts.pending[path] == nil || tracer == nil {
		t.Fatal("fixture did not stage a blocked transcript line")
	}
	if err := ts.saveOffsets(offsets); err != nil {
		t.Fatal(err)
	}
	first := <-sub
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deleted := false
	ts.ExtraTargets = func() []string {
		if !deleted {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			deleted = true
		} else if ts.pending[path] == nil {
			cancel() // this resolve must retire the now-delivered source
		} else if ts.tracers[path] != tracer {
			t.Fatal("retired parser before staged events were delivered")
		}
		return nil
	}
	ts.tailEvery, ts.resolveEvery = time.Millisecond, 2*time.Millisecond
	if err := ts.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("scanner failed to deliver and retire the deleted source: %v", err)
	}
	second := <-sub
	if first.Kind != event.KindModelCall || second.Kind != event.KindToolCall || second.CallID != "tool" || second.SessionID != "pending-session" {
		t.Fatalf("staged events changed: %+v, %+v", first, second)
	}
	if ts.pending[path] != nil {
		t.Fatal("delivered line stayed pending")
	}
	if ts.tracers[path] != nil || len(ts.loadOffsets()) != 0 {
		t.Fatal("deleted source retained state after delivery")
	}
}

func TestTranscriptRecreatedSourceDoesNotReuseMessageState(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "projects", "repo", "session.jsonl")
	b := bus.New(8)
	defer b.Close()
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.OffsetStatePath = filepath.Join(home, "offsets.json")
	offsets := map[string]int64{}
	line := func(id string) string {
		return fmt.Sprintf(`{"sessionId":%q,"type":"assistant","message":{"id":"reused-message","model":"m-test","usage":{"input_tokens":1,"output_tokens":1},"content":[]}}`, id)
	}
	appendTranscriptEvents(t, ts, sub, offsets, path, line("old-session"))
	if err := ts.saveOffsets(offsets); err != nil {
		t.Fatal(err)
	}
	ts.ExtraTargets = func() []string {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	resolveTranscriptState(t, ts)
	events := appendTranscriptEvents(t, ts, sub, ts.loadOffsets(), path, line("new-session"))
	if len(events) != 1 || events[0].Kind != event.KindModelCall || events[0].SessionID != "new-session" {
		t.Fatalf("recreated source reused retired message state: %+v", events)
	}
}

func TestTranscriptStatFailureRetainsState(t *testing.T) {
	home := t.TempDir()
	parent := filepath.Join(home, "restricted")
	path := filepath.Join(parent, ".claude", "projects", "repo", "session.jsonl")
	writeTranscriptSource(t, path, `{"sessionId":"retained","type":"user","message":{"content":"hello"}}`)
	b := bus.New(8)
	defer b.Close()
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.OffsetStatePath = filepath.Join(home, "offsets.json")
	offsets := map[string]int64{}
	ts.tailFile(path, offsets, nil)
	<-sub
	tracer := ts.tracers[path]
	if err := ts.saveOffsets(offsets); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0o700)
	if _, err := os.Stat(path); !os.IsPermission(err) {
		t.Skip("execution identity bypasses directory permissions")
	}
	resolveTranscriptState(t, ts)
	if ts.tracers[path] != tracer || ts.loadOffsets()[path] != offsets[path] {
		t.Fatal("an inaccessible source was treated as deleted")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	events := appendTranscriptEvents(t, ts, sub, ts.loadOffsets(), path, `{"sessionId":"retained","type":"user","message":{"content":"resumed"}}`)
	if len(events) != 1 || events[0].Kind != event.KindTurn || events[0].SessionID != "retained" {
		t.Fatalf("restored access skipped new activity or replayed history: %+v", events)
	}
}
