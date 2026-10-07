package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func rekeyFixture(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, id := range []string{"old", "new"} {
		if err := s.UpsertSession(model.Session{ID: id, StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestRekeyMergesCallsAndAllReferences(t *testing.T) {
	s := rekeyFixture(t)
	now := time.Now()
	s.PutEvent(event.Event{Kind: event.KindToolCall, SessionID: "new", CallID: "tool", TS: now, ToolName: "Read", ToolStatus: "running"})
	s.PutEvent(event.Event{Kind: event.KindToolCall, SessionID: "old", CallID: "tool", TS: now, ToolName: "Read", ToolStatus: "ok", DurationMs: 50})
	s.PutEvent(event.Event{Kind: event.KindModelCall, SessionID: "new", CallID: "model", TS: now, TokensIn: 10, TokensOut: 5})
	s.PutEvent(event.Event{Kind: event.KindModelCall, SessionID: "old", CallID: "model", TS: now, Model: "claude-sonnet", Provider: "anthropic", TokensIn: 20, TokensOut: 3, CostUSD: 0.02})
	s.PutEvent(event.Event{Kind: event.KindModelCall, SessionID: "new", CallID: "known", TS: now, Model: "canonical-model", Provider: "canonical-provider"})
	s.PutEvent(event.Event{Kind: event.KindModelCall, SessionID: "old", CallID: "known", TS: now, Model: "provisional-model", Provider: "provisional-provider"})
	for _, q := range []string{
		`INSERT INTO guard_decisions VALUES ('g','old','r','deny','once','2026-10-07T00:00:00Z')`,
		`INSERT INTO incidents (id,session_id,report_json) VALUES ('i','old','{"session_id":"old","summary":"old remains literal text"}')`,
		`INSERT INTO egress_episodes VALUES ('e','','','','','host','tcp',443,1,1,2,'[]','["old","new","other"]')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RekeySession("old", "new"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetSession("old"); ok {
		t.Fatal("old session retained")
	}
	var old, count, in, out, dur int
	var status string
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE session_id='old'`).Scan(&old); err != nil || old != 0 {
		t.Fatalf("orphan events: %d, %v", old, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*),tokens_in,tokens_out FROM events WHERE session_id='new' AND call_id='model'`).Scan(&count, &in, &out); err != nil || count != 1 || in != 20 || out != 5 {
		t.Fatalf("merged usage: %d %d %d, %v", count, in, out, err)
	}
	if err := s.db.QueryRow(`SELECT tool_status,duration_ms FROM events WHERE session_id='new' AND call_id='tool'`).Scan(&status, &dur); err != nil || status != "ok" || dur != 50 {
		t.Fatalf("completion lost: %s %d, %v", status, dur, err)
	}
	var model, provider string
	if err := s.db.QueryRow(`SELECT COALESCE(model,''),COALESCE(provider,'') FROM events WHERE session_id='new' AND call_id='model'`).Scan(&model, &provider); err != nil || model != "claude-sonnet" || provider != "anthropic" {
		t.Fatalf("known call metadata lost: %q %q, %v", model, provider, err)
	}
	if err := s.db.QueryRow(`SELECT model,provider FROM events WHERE session_id='new' AND call_id='known'`).Scan(&model, &provider); err != nil || model != "canonical-model" || provider != "canonical-provider" {
		t.Fatalf("canonical metadata overwritten: %q %q, %v", model, provider, err)
	}
	for _, q := range []string{
		`SELECT COUNT(*) FROM guard_decisions WHERE session_id='new'`,
		`SELECT COUNT(*) FROM incidents WHERE session_id='new' AND json_extract(report_json,'$.session_id')='new' AND json_extract(report_json,'$.summary')='old remains literal text'`,
		`SELECT COUNT(*) FROM egress_episodes WHERE session_ids_json='["new","other"]'`,
	} {
		if err := s.db.QueryRow(q).Scan(&count); err != nil || count != 1 {
			t.Fatalf("reference not moved: %s: %d %v", q, count, err)
		}
	}
}

func TestRekeyFailureRollsBackAndRecoversHealth(t *testing.T) {
	s := rekeyFixture(t)
	s.PutEvent(event.Event{Kind: event.KindFileOpen, SessionID: "old", TS: time.Now()})
	if _, err := s.db.Exec(`CREATE TRIGGER fail_rekey BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'injected rekey failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RekeySession("old", "new"); err == nil {
		t.Fatal("failed rekey returned success")
	}
	if _, ok := s.GetSession("old"); !ok {
		t.Fatal("failed rekey deleted old session")
	}
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"session rekeys"}) {
		t.Fatalf("failure hidden: %+v", h)
	}
	if err := s.RekeySession("", "new"); err != nil {
		t.Fatal(err)
	}
	h = s.WriteHealth()
	if len(h.Active) != 1 {
		t.Fatalf("no-op cleared failure: %+v", h)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_rekey`); err != nil {
		t.Fatal(err)
	}
	if err := s.RekeySession("old", "new"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetSession("old"); ok {
		t.Fatal("retry retained old session")
	}
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("recovery health: %+v", h)
	}
}
