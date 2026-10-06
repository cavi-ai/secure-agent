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

func TestProcessTreeCreationRetriesFailedPersistence(t *testing.T) {
	for _, rootStart := range []string{"aged", "unknown"} {
		for _, failure := range []struct{ name, sql string }{
			{"aborted", "ABORT, 'injected creation failure'"},
			{"ignored", "IGNORE"},
		} {
			t.Run(rootStart+"/"+failure.name, func(t *testing.T) {
				dbPath := filepath.Join(t.TempDir(), "events.db")
				st, err := store.Open(dbPath, "")
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				now := time.Now().UTC()
				started := now.Add(-time.Hour)
				if rootStart == "unknown" {
					started = time.Time{}
				}
				cfg, _ := config.Load("/nonexistent")
				tagger := agents.New(cfg, fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: started}})
				tagger.Refresh()
				r := NewResolver(st, tagger)
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec("CREATE TRIGGER fail_creation BEFORE INSERT ON sessions BEGIN SELECT RAISE(" + failure.sql + "); END"); err != nil {
					t.Fatal(err)
				}
				var emitted []model.Session
				r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
				e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: now}
				id := r.Resolve(&e)
				if id == "" || e.SessionID != id {
					t.Fatal("failed persistence lost event attribution")
				}
				if _, ok := st.GetSession(id); ok || len(emitted) != 0 {
					t.Fatalf("failed creation saved or published a session: %+v", emitted)
				}
				if pending, ok := r.deferred[id]; !ok || pending.Workspace != "/repo" || pending.RootPID != 100 {
					t.Fatalf("failed creation lost pending identity: %+v", pending)
				}
				if _, ok := r.touch[id]; ok {
					t.Fatal("failed creation advanced activity throttle")
				}
				if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "sessions" {
					t.Fatalf("creation failure hidden or attempted more than once: %+v", h)
				}
				if _, err := db.Exec("DROP TRIGGER fail_creation"); err != nil {
					t.Fatal(err)
				}
				retry := event.Event{Kind: event.KindFileOpen, PID: 100, TS: now.Add(time.Second)}
				if retried := r.Resolve(&retry); retried != id {
					t.Fatalf("retry changed attribution: %q, want %q", retried, id)
				}
				saved, ok := st.GetSession(id)
				if !ok || !saved.LastSeenAt.Equal(retry.TS) || saved.Workspace != "/repo" || len(emitted) != 1 || emitted[0] != saved {
					t.Fatalf("retry did not persist and publish identity: saved=%+v deltas=%+v", saved, emitted)
				}
				if _, ok := r.deferred[id]; ok || !r.touch[id].Equal(retry.TS) {
					t.Fatal("saved creation did not retire retry state")
				}
				if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
					t.Fatalf("creation recovery lost fault history or retained fault: %+v", h)
				}
			})
		}
	}
}

func TestProcessTreeCreationPublishesStoredIdentity(t *testing.T) {
	now := time.Now().UTC()
	started := now.Add(-time.Hour)
	r, st := testResolver(t, fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: started}})
	sess := model.Session{ID: ProcSessionID(100, started), Harness: "claude", Repo: "hook-repo", Confidence: model.ConfHook, Status: model.SessionEnded, StartedAt: started, LastSeenAt: now}
	if err := st.UpsertSession(sess); err != nil {
		t.Fatal(err)
	}
	var emitted []model.Session
	r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: now}
	r.Resolve(&e)
	if len(emitted) != 1 || emitted[0].Status != sess.Status || emitted[0].Repo != sess.Repo || emitted[0].Confidence != sess.Confidence {
		t.Fatalf("creation published incoming identity instead of saved identity: %+v", emitted)
	}
}

func TestProcessTreeCreationJoinsRecentlyTouchedTranscript(t *testing.T) {
	now := time.Now().UTC()
	r, st := testResolver(t, fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: now.Add(-time.Hour)}})
	r.NoteTranscriptSession("conversation", "claude", "/repo", now)
	var emitted []model.Session
	r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: now.Add(time.Second)}
	if id := r.Resolve(&e); id != "conversation" {
		t.Fatalf("process tree did not adopt transcript identity: %q", id)
	}
	saved, _ := st.GetSession("conversation")
	if saved.RootPID != 100 || len(emitted) != 1 || emitted[0].RootPID != saved.RootPID || !saved.LastSeenAt.Equal(e.TS) {
		t.Fatalf("activity throttle prevented root attachment: saved=%+v deltas=%+v", saved, emitted)
	}
}
