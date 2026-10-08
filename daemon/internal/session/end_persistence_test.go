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

func TestResolverEndingFailureRetainsTrackingAndAllowsRecovery(t *testing.T) {
	for _, path := range []string{"tracked root", "restarted root", "silent session", "transcript"} {
		t.Run(path, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "events.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			now := time.Now().UTC()
			sess := model.Session{ID: "session", RootPID: 100, Status: model.SessionActive, StartedAt: now, LastSeenAt: now}
			if path == "silent session" {
				sess.RootPID, sess.Status, sess.LastSeenAt = 0, model.SessionIdle, now.Add(-48*time.Hour)
			}
			if path == "transcript" {
				sess.RootPID = 0
			}
			st.UpsertSession(sess)
			st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: sess.ID, CallID: "call", ToolName: "Read", ToolStatus: "running"})
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`CREATE TRIGGER fail_call_close BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'injected call-close failure'); END`); err != nil {
				t.Fatal(err)
			}
			cfg, _ := config.Load("/nonexistent")
			tagger := agents.New(cfg, fakeProcs{})
			tagger.Refresh()
			r := NewResolver(st, tagger)
			r.now = func() time.Time { return now }
			r.touch[sess.ID] = now
			if path == "tracked root" {
				r.byRoot[100], r.byPID[101], r.byScope["scope"] = sess.ID, sess.ID, sess.ID
			}
			if path == "transcript" {
				r.byScope["scope"] = sess.ID
			}
			var emitted []model.Session
			r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
			end := func() {
				if path == "transcript" {
					r.EndTranscriptSession(sess.ID, now)
				} else {
					r.Sweep()
				}
			}
			end()
			if !r.touch[sess.ID].Equal(now) {
				t.Fatal("failed ending dropped activity throttle")
			}
			if len(emitted) != 0 {
				t.Fatalf("failed ending emitted a lifecycle transition: %+v", emitted)
			}
			if saved, ok := st.GetSession(sess.ID); !ok || saved.Status != sess.Status || saved.EndedAt != nil {
				t.Fatalf("failed ending changed saved session: %+v, %v", saved, ok)
			}
			if path == "tracked root" && (r.byRoot[100] != sess.ID || r.byPID[101] != sess.ID || r.byScope["scope"] != sess.ID) {
				t.Fatal("failed ending dropped process tracking")
			}
			if path == "transcript" && r.byScope["scope"] != sess.ID {
				t.Fatal("failed transcript ending dropped scope tracking")
			}
			if _, err := db.Exec("DROP TRIGGER fail_call_close"); err != nil {
				t.Fatal(err)
			}
			end()
			if len(emitted) != 1 || emitted[0].Status != model.SessionEnded {
				t.Fatalf("recovered ending did not emit persisted state: %+v", emitted)
			}
			if saved, ok := st.GetSession(sess.ID); !ok || saved.Status != model.SessionEnded {
				t.Fatalf("ending did not recover: %+v, %v", saved, ok)
			}
			if (path == "tracked root" && (len(r.byRoot) != 0 || len(r.byPID) != 0)) || len(r.byScope) != 0 {
				t.Fatal("successful ending retained tracking")
			}
			if len(r.touch) != 0 {
				t.Fatal("successful ending retained activity throttle")
			}
			if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
				t.Fatalf("ending recovery lost failure history or retained a fault: %+v", h)
			}
		})
	}
}
