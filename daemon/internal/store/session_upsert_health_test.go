package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionUpsertFailureAndRecovery(t *testing.T) {
	for _, failure := range []string{"read", "read-only", "ignored insert", "ignored update"} {
		t.Run(failure, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Now().UTC()
			sess := model.Session{ID: "session", StartedAt: now, LastSeenAt: now}
			var inject, recover string
			switch failure {
			case "read":
				inject, recover = "ALTER TABLE sessions RENAME TO unavailable_sessions", "ALTER TABLE unavailable_sessions RENAME TO sessions"
			case "read-only":
				inject, recover = "PRAGMA query_only = ON", "PRAGMA query_only = OFF"
			case "ignored insert":
				inject, recover = "CREATE TRIGGER skip_upsert BEFORE INSERT ON sessions BEGIN SELECT RAISE(IGNORE); END", "DROP TRIGGER skip_upsert"
			case "ignored update":
				if err := s.UpsertSession(sess); err != nil {
					t.Fatal(err)
				}
				sess.LastSeenAt = now.Add(time.Minute)
				inject, recover = "CREATE TRIGGER skip_upsert BEFORE UPDATE ON sessions BEGIN SELECT RAISE(IGNORE); END", "DROP TRIGGER skip_upsert"
			}
			if _, err := s.db.Exec(inject); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertSession(sess); err == nil {
				t.Fatal("unsaved upsert reported success")
			}
			if err := s.UpsertSession(model.Session{}); err != nil {
				t.Fatal(err)
			}
			if h := s.WriteHealth(); h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "sessions" {
				t.Fatalf("upsert fault hidden or cleared by no-op: %+v", h)
			}
			if _, err := s.db.Exec(recover); err != nil {
				t.Fatal(err)
			}
			if saved, ok := s.GetSession(sess.ID); failure == "ignored update" {
				if !ok || !saved.LastSeenAt.Equal(now) {
					t.Fatalf("ignored update changed saved state: %+v", saved)
				}
			} else if ok {
				t.Fatalf("failed insert saved a row: %+v", saved)
			}
			if err := s.UpsertSession(sess); err != nil {
				t.Fatal(err)
			}
			if saved, ok := s.GetSession(sess.ID); !ok || !saved.LastSeenAt.Equal(sess.LastSeenAt) {
				t.Fatalf("retry did not save session: %+v", saved)
			}
			if h := s.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
				t.Fatalf("retry lost fault history or retained fault: %+v", h)
			}
		})
	}
}
