package collect

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func openclawRetryFixture(t *testing.T) (string, *sql.DB, string) {
	t.Helper()
	dir, db := openclawFixture(t)
	state := filepath.Join(t.TempDir(), "openclaw-watermark.json")
	seed, sub, _, _ := newTestOpenclaw(t, dir)
	seed.StatePath = state
	if n := seed.pollOnce(); n != 7 {
		t.Fatalf("seed poll published %d, want existing 7 events", n)
	}
	drainOpenclaw(sub, 7)
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("seed collector did not persist its checkpoint: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO messages (message_id, conversation_id, seq, role, content, token_count, created_at)
		VALUES (7, 2, 2, 'user', 'x', 2, '2026-09-23 07:02:00');
		INSERT INTO message_parts (part_id, message_id, session_id, part_type, ordinal, step_cost, step_tokens_in, step_tokens_out, metadata)
		VALUES ('p8', 7, 'x', 'step_finish', 0, 0.001, 1, 2, '{"modelId":"fixture-model","modelProvider":"fixture-provider"}')`); err != nil {
		t.Fatal(err)
	}
	return dir, db, state
}

func receiveCollectorRetryEvent(t *testing.T, ch <-chan event.Event) event.Event {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for collector event")
		return event.Event{}
	}
}

func TestOpenclawRetriesRejectedMultiEventRowOnUnchangedDatabase(t *testing.T) {
	dir, _, state := openclawRetryFixture(t)
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	c, _, _, _ := newTestOpenclaw(t, dir)
	c.bus, c.StatePath = b, state
	c.loadState()
	c.now = func() time.Time { return time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC) }

	if n := c.pollOnce(); n != 1 {
		t.Fatalf("first poll accepted %d events, want the turn prefix", n)
	}
	if got := receiveCollectorRetryEvent(t, sub); got.Kind != event.KindTurn || got.SessionID != "s-mar" || got.ObservedTS {
		t.Fatalf("accepted prefix = %+v, want the session turn", got)
	}
	if n := c.pollOnce(); n != 1 {
		t.Fatalf("unchanged-source retry accepted %d events, want the pending model call", n)
	}
	if got := receiveCollectorRetryEvent(t, sub); got.Kind != event.KindModelCall || got.TokensIn != 1 || got.TokensOut != 2 || got.Model != "fixture-model" {
		t.Fatalf("pending suffix = %+v, want model-call event from the same source row", got)
	}
	if c.watermark != 7 {
		t.Fatalf("watermark = %d, want 7 after every row event was accepted", c.watermark)
	}

	resumed, resumedSub, _, _ := newTestOpenclaw(t, dir)
	resumed.StatePath = state
	resumed.loadState()
	if n := resumed.pollOnce(); n != 0 || len(resumedSub) != 0 {
		t.Fatalf("completed checkpoint replayed the row: count=%d queued=%d", n, len(resumedSub))
	}
}

func TestOpenclawReloadRetriesRejectedRowFromPersistedCheckpoint(t *testing.T) {
	dir, _, state := openclawRetryFixture(t)
	b1 := bus.New(1)
	defer b1.Close()
	sub1 := b1.Subscribe()
	c1, _, _, _ := newTestOpenclaw(t, dir)
	c1.bus, c1.StatePath = b1, state
	c1.loadState()
	c1.now = func() time.Time { return time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC) }
	c1.pollOnce()
	if got := receiveCollectorRetryEvent(t, sub1); got.Kind != event.KindTurn {
		t.Fatalf("accepted prefix = %+v, want turn", got)
	}

	// Simulate a process restart before the row suffix is accepted. The new
	// collector must resume from the saved source checkpoint. Replaying the
	// already accepted prefix across a crash is allowed; skipping the suffix is not.
	b2 := bus.New(1)
	defer b2.Close()
	sub2 := b2.Subscribe()
	c2, _, _, _ := newTestOpenclaw(t, dir)
	c2.bus, c2.StatePath = b2, state
	c2.loadState()
	c2.now = func() time.Time { return time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC) }
	var got []event.Event
	for range 3 {
		c2.pollOnce()
		select {
		case e := <-sub2:
			got = append(got, e)
		default:
		}
		if len(got) == 2 {
			break
		}
	}
	if len(got) != 2 || got[0].Kind != event.KindTurn || got[1].Kind != event.KindModelCall || got[1].TokensIn != 1 || got[1].TokensOut != 2 {
		t.Fatalf("restarted collector events = %+v, want turn and model call from the persisted row", got)
	}

	var persisted openclawState
	data, err := os.ReadFile(state)
	if err != nil || json.Unmarshal(data, &persisted) != nil || persisted.MessageID != 7 {
		t.Fatalf("completed row checkpoint = %s, %v; want message_id 7", data, err)
	}
}

func TestOpenclawPersistsFirstSightBoundaryBeforeDelivery(t *testing.T) {
	dir, db, _ := openclawRetryFixture(t)
	if _, err := db.Exec(`UPDATE messages SET created_at='2026-09-25 07:59:00' WHERE message_id=7`); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "first-sight-watermark.json")
	clock := func(day int) func() time.Time {
		return func() time.Time { return time.Date(2026, 9, day, 8, 0, 0, 0, time.UTC) }
	}
	b1 := bus.New(1)
	defer b1.Close()
	sub1 := b1.Subscribe()
	c1, _, _, _ := newTestOpenclaw(t, dir)
	c1.bus, c1.StatePath, c1.now = b1, state, clock(25)
	if n := c1.pollOnce(); n != 1 {
		t.Fatalf("initial poll accepted %d events, want the turn prefix", n)
	}
	if got := receiveCollectorRetryEvent(t, sub1); got.Kind != event.KindTurn {
		t.Fatalf("initial accepted prefix = %+v, want turn", got)
	}

	var baseline openclawState
	data, err := os.ReadFile(state)
	if err != nil || json.Unmarshal(data, &baseline) != nil || baseline.MessageID != 6 {
		t.Fatalf("first-sight baseline = %s, %v; want message_id 6 before delivery completes", data, err)
	}

	b2 := bus.New(1)
	defer b2.Close()
	sub2 := b2.Subscribe()
	c2, _, _, _ := newTestOpenclaw(t, dir)
	c2.bus, c2.StatePath, c2.now = b2, state, clock(27)
	c2.loadState()
	var got []event.Event
	for range 3 {
		c2.pollOnce()
		select {
		case e := <-sub2:
			got = append(got, e)
		default:
		}
		if len(got) == 2 {
			break
		}
	}
	if len(got) != 2 || got[0].Kind != event.KindTurn || got[1].Kind != event.KindModelCall {
		t.Fatalf("events after restart past first-sight window = %+v, want turn and model call", got)
	}
}

func TestOpenclawMarksInvalidEventTimestampObserved(t *testing.T) {
	dir, db, state := openclawRetryFixture(t)
	if _, err := db.Exec(`UPDATE messages SET created_at='invalid time' WHERE message_id=7`); err != nil {
		t.Fatal(err)
	}
	b := bus.New(4)
	defer b.Close()
	sub := b.Subscribe()
	c, _, _, _ := newTestOpenclaw(t, dir)
	c.bus, c.StatePath = b, state
	c.loadState()
	if n := c.pollOnce(); n != 2 {
		t.Fatalf("invalid-timestamp row accepted %d events, want turn and model call", n)
	}
	for i := 0; i < 2; i++ {
		if e := receiveCollectorRetryEvent(t, sub); !e.ObservedTS {
			t.Fatalf("event %d = %+v, want observed timestamp fallback", i, e)
		}
	}
}
