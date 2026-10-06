package session

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestDeferredPromotionRetriesFailedPersistence(t *testing.T) {
	for _, tagged := range []bool{true, false} {
		rootState := "live"
		if !tagged {
			rootState = "exited"
		}
		for _, failure := range []struct{ name, sql string }{
			{"aborted", "ABORT, 'injected promotion failure'"},
			{"ignored", "IGNORE"},
		} {
			t.Run(rootState+"/"+failure.name, func(t *testing.T) {
				dbPath := filepath.Join(t.TempDir(), "events.db")
				st, err := store.Open(dbPath, "")
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				started := time.Now().UTC()
				procs := fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: started}}
				cfg, _ := config.Load("/nonexistent")
				tagger := agents.New(cfg, procs)
				tagger.Refresh()
				r := NewResolver(st, tagger)
				e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: started}
				id := r.Resolve(&e)
				if id == "" || len(r.deferred) != 1 {
					t.Fatal("young root was not deferred")
				}
				if !tagged {
					delete(procs, 100)
					tagger.Refresh()
				}
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec("CREATE TRIGGER fail_promotion BEFORE INSERT ON sessions BEGIN SELECT RAISE(" + failure.sql + "); END"); err != nil {
					t.Fatal(err)
				}
				var emitted []model.Session
				r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
				attempt := started.Add(2 * time.Minute)
				r.touchLocked(id, attempt)
				if _, ok := st.GetSession(id); ok || len(emitted) != 0 {
					t.Fatalf("failed promotion saved or published a session: %+v", emitted)
				}
				if _, ok := r.deferred[id]; !ok {
					t.Fatal("failed promotion discarded retry state")
				}
				if !r.touch[id].Equal(started) {
					t.Fatal("failed promotion advanced throttle")
				}
				if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "sessions" {
					t.Fatalf("promotion failure hidden: %+v", h)
				}
				if _, err := db.Exec("DROP TRIGGER fail_promotion"); err != nil {
					t.Fatal(err)
				}
				retry := attempt.Add(time.Second)
				r.touchLocked(id, retry)
				saved, ok := st.GetSession(id)
				if !ok || !saved.LastSeenAt.Equal(retry) || len(emitted) != 1 || !emitted[0].LastSeenAt.Equal(saved.LastSeenAt) {
					t.Fatalf("retry did not persist and publish current activity: saved=%+v deltas=%+v", saved, emitted)
				}
				if _, ok := r.deferred[id]; ok || !r.touch[id].Equal(retry) {
					t.Fatal("successful promotion did not retire retry state")
				}
				if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
					t.Fatalf("promotion recovery lost fault history or retained fault: %+v", h)
				}
			})
		}
	}
}

func TestDeferredPromotionPublishesStoredIdentity(t *testing.T) {
	now := time.Now().UTC()
	r, st := testResolver(t, fakeProcs{})
	saved := model.Session{ID: "session", Harness: "claude", Repo: "hook-repo", Status: model.SessionEnded, Confidence: model.ConfHook, StartedAt: now.Add(-time.Hour), LastSeenAt: now}
	if err := st.UpsertSession(saved); err != nil {
		t.Fatal(err)
	}
	r.deferred[saved.ID] = model.Session{ID: saved.ID, RootStartedAt: saved.StartedAt.Format(time.RFC3339Nano), StartedAt: saved.StartedAt, Status: model.SessionActive, Confidence: model.ConfProcessTree}
	var emitted []model.Session
	r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
	r.touchLocked(saved.ID, now)
	if len(emitted) != 1 || emitted[0].Status != saved.Status || emitted[0].Repo != saved.Repo || emitted[0].Confidence != saved.Confidence {
		t.Fatalf("promotion published incoming identity instead of saved identity: %+v", emitted)
	}
}
