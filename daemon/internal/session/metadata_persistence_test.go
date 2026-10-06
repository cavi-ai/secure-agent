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

func TestSessionMetadataPublishesOnlyAfterPersistence(t *testing.T) {
	for _, path := range []string{"handshake", "transcript", "stamped", "join", "older join"} {
		for _, failure := range []struct{ name, sql string }{
			{"aborted", "ABORT, 'injected metadata failure'"},
			{"ignored", "IGNORE"},
		} {
			t.Run(path+"/"+failure.name, func(t *testing.T) {
				dbPath := filepath.Join(t.TempDir(), "events.db")
				st, err := store.Open(dbPath, "")
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				now := time.Now().UTC()
				original := model.Session{ID: "conversation", Harness: "claude", Workspace: "/repo", Repo: "saved-repo", Branch: "saved-branch", Confidence: model.ConfTranscript, Status: model.SessionIdle, StartedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-time.Minute)}
				if err := st.UpsertSession(original); err != nil {
					t.Fatal(err)
				}
				cfg, _ := config.Load("/nonexistent")
				tagger := agents.New(cfg, fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: now.Add(-time.Hour)}})
				tagger.Refresh()
				r := NewResolver(st, tagger)
				r.now = func() time.Time { return now }
				if path == "older join" {
					if err := st.UpsertSession(model.Session{ID: "newer", Harness: "claude", Confidence: model.ConfTranscript, RootPID: 100, StartedAt: now, LastSeenAt: now}); err != nil {
						t.Fatal(err)
					}
					r.byRoot[100] = "newer"
				}
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec("CREATE TRIGGER fail_metadata BEFORE INSERT ON sessions BEGIN SELECT RAISE(" + failure.sql + "); END"); err != nil {
					t.Fatal(err)
				}
				var emitted []model.Session
				r.OnSessionChange = func(s model.Session) { emitted = append(emitted, s) }
				attempt := func(ts time.Time) {
					switch path {
					case "handshake":
						r.HandleHandshake(Handshake{SessionID: original.ID, Harness: "claude", Workspace: "/repo", Repo: "updated-repo", Branch: "updated-branch", TS: ts})
					case "transcript":
						r.NoteTranscriptSighting(TranscriptSighting{ID: original.ID, Harness: "claude", Workspace: "/repo", Repo: "updated-repo", Branch: "updated-branch", TS: ts})
					case "stamped":
						e := event.Event{SessionID: original.ID, Kind: event.KindFileOpen, TS: ts}
						if id := r.Resolve(&e); id != original.ID {
							t.Fatalf("failed metadata save lost attribution: %q", id)
						}
					default:
						r.JoinTranscriptPID(original.ID, 100)
					}
				}
				attempt(now)
				if len(emitted) != 0 {
					t.Fatalf("failed metadata write published a session: %+v", emitted)
				}
				if saved, ok := st.GetSession(original.ID); !ok || saved != original {
					t.Fatalf("failed metadata write changed saved state: %+v", saved)
				}
				if _, ok := r.touch[original.ID]; ok {
					t.Fatal("failed metadata write advanced activity throttle")
				}
				if path == "handshake" || path == "transcript" || path == "stamped" {
					if count := r.SightedByHarness(now)["claude"]; count != 1 {
						t.Fatalf("failed save lost the observed sighting: %d", count)
					}
				}
				if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "sessions" {
					t.Fatalf("metadata fault hidden: %+v", h)
				}
				if _, err := db.Exec("DROP TRIGGER fail_metadata"); err != nil {
					t.Fatal(err)
				}
				attempt(now.Add(time.Second))
				saved, _ := st.GetSession(original.ID)
				if len(emitted) != 1 || emitted[0] != saved {
					t.Fatalf("retry did not publish saved state: saved=%+v deltas=%+v", saved, emitted)
				}
				switch path {
				case "handshake", "transcript":
					if saved.Repo != "updated-repo" || saved.Branch != "updated-branch" || !saved.LastSeenAt.Equal(now.Add(time.Second)) {
						t.Fatalf("metadata retry was not saved: %+v", saved)
					}
				case "stamped":
					if saved.Confidence != model.ConfHook || !saved.LastSeenAt.Equal(now.Add(time.Second)) {
						t.Fatalf("stamped retry was not saved: %+v", saved)
					}
				default:
					if saved.RootPID != 100 {
						t.Fatalf("root attachment was not retried: %+v", saved)
					}
					if path == "older join" && r.byRoot[100] != "newer" {
						t.Fatal("older conversation took the newer conversation's root")
					}
				}
				if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
					t.Fatalf("retry lost fault history or retained fault: %+v", h)
				}
			})
		}
	}
}
