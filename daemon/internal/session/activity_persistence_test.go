package session

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestResolverIdleAndActivityWriteRecovery(t *testing.T) {
	for _, path := range []string{"idle", "activity"} {
		t.Run(path, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "events.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			now := time.Now().UTC()
			status := model.SessionActive
			if path == "activity" {
				status = model.SessionIdle
			}
			lastSeen := now.Add(-idleAfter - time.Minute)
			st.UpsertSession(model.Session{ID: "session", Harness: "claude", RootPID: 100, Status: status, StartedAt: lastSeen, LastSeenAt: lastSeen})
			cfg, _ := config.Load("/nonexistent")
			tagger := agents.New(cfg, fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: now.Add(-time.Hour)}})
			tagger.Refresh()
			r := NewResolver(st, tagger)
			r.now = func() time.Time { return now }
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`CREATE TRIGGER fail_session_update BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'injected session update failure'); END`); err != nil {
				t.Fatal(err)
			}
			var emitted []model.Session
			r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
			attempt := func(ts time.Time) {
				if path == "idle" {
					r.Sweep()
				} else {
					r.mu.Lock()
					r.touchLocked("session", ts)
					r.mu.Unlock()
				}
			}
			attempt(now)
			if len(emitted) != 0 {
				t.Fatalf("failed write emitted a session transition: %+v", emitted)
			}
			if saved, _ := st.GetSession("session"); saved.Status != status || !saved.LastSeenAt.Equal(lastSeen) {
				t.Fatalf("failed write changed saved state: %+v", saved)
			}
			if path == "activity" {
				if _, ok := r.touch["session"]; ok {
					t.Fatal("failed activity write advanced throttle clock")
				}
			}
			if _, err := db.Exec("DROP TRIGGER fail_session_update"); err != nil {
				t.Fatal(err)
			}
			attempt(now.Add(time.Second))
			saved, _ := st.GetSession("session")
			if path == "idle" {
				if saved.Status != model.SessionIdle || len(emitted) != 1 || emitted[0].Status != model.SessionIdle {
					t.Fatalf("idle recovery did not publish saved state: saved=%+v deltas=%+v", saved, emitted)
				}
			} else if saved.Status != model.SessionActive || !saved.LastSeenAt.Equal(now.Add(time.Second)) || !r.touch["session"].Equal(now.Add(time.Second)) {
				t.Fatalf("failed touch was not retried before the throttle window: %+v", saved)
			}
			if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
				t.Fatalf("recovery lost history or retained fault: %+v", h)
			}
		})
	}
}
