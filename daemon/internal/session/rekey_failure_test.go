package session

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestDeferredRekeyFailurePreservesEvidenceAndIndices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := NewResolver(st, nil)
	now := time.Now()
	r.deferred["old"] = model.Session{ID: "old", Harness: "claude", Workspace: "/repo", RootPID: 100, StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfProcessTree}
	r.byPID[100], r.byRoot[100], r.byScope[scopeKey("claude", "/repo")] = "old", "old", "old"
	r.touch["old"] = now
	st.PutEvent(event.Event{Kind: event.KindFileOpen, SessionID: "old", TS: now})
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER fail_promotion BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'injected promotion failure'); END`); err != nil {
		t.Fatal(err)
	}
	r.HandleHandshake(Handshake{SessionID: "new", Harness: "claude", Workspace: "/repo", PID: 100, TS: now})
	if r.byPID[100] != "old" || r.byRoot[100] != "old" || r.byScope[scopeKey("claude", "/repo")] != "old" || r.deferred["old"].ID != "old" {
		t.Fatal("failed promotion changed resolver indices")
	}
	if !r.touch["old"].Equal(now) {
		t.Fatal("failed promotion dropped activity throttle")
	}
	events := st.RecentEvents(10)
	if len(events) != 1 || events[0].SessionID != "old" {
		t.Fatalf("failed promotion rekeyed evidence: %+v", events)
	}
	if _, ok := st.GetSession("new"); ok {
		t.Fatal("failed promotion created canonical session")
	}
	if _, err := db.Exec(`DROP TRIGGER fail_promotion`); err != nil {
		t.Fatal(err)
	}
	r.HandleHandshake(Handshake{SessionID: "new", Harness: "claude", Workspace: "/repo", PID: 100, TS: now})
	if r.byPID[100] != "new" || r.byRoot[100] != "new" {
		t.Fatal("promotion retry did not update resolver")
	}
	if _, ok := r.deferred["old"]; ok {
		t.Fatal("promotion retained deferred session")
	}
	if _, ok := r.touch["old"]; ok {
		t.Fatal("promotion retained retired identity's activity throttle")
	}
	if events := st.RecentEvents(10); len(events) != 1 || events[0].SessionID != "new" {
		t.Fatalf("promotion retry evidence: %+v", events)
	}
}
