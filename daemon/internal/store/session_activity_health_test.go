package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionIdleAndActivityFaultsRecoverIndependently(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	s.UpsertSession(model.Session{ID: "active", Status: model.SessionActive, StartedAt: now, LastSeenAt: now})
	s.UpsertSession(model.Session{ID: "idle", Status: model.SessionIdle, StartedAt: now, LastSeenAt: now})
	s.UpsertSession(model.Session{ID: "ended", Status: model.SessionEnded, StartedAt: now, LastSeenAt: now})
	if _, err := s.db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.MarkSessionsIdle(now.Add(time.Minute)); err == nil || len(ids) != 0 {
		t.Fatalf("failed idle write returned changed sessions or no error: %v, %v", ids, err)
	}
	if err := s.TouchSession("idle", now.Add(time.Minute)); err == nil {
		t.Fatal("failed activity write reported success")
	}
	if saved, _ := s.GetSession("active"); saved.Status != model.SessionActive {
		t.Fatalf("failed idle write changed saved state: %+v", saved)
	}
	if saved, _ := s.GetSession("idle"); saved.Status != model.SessionIdle || !saved.LastSeenAt.Equal(now) {
		t.Fatalf("failed activity write changed saved state: %+v", saved)
	}
	h := s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"session activity", "session idling"}) {
		t.Fatalf("lifecycle failures hidden: %+v", h)
	}
	if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchSession("missing", now); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchSession("ended", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.MarkSessionsIdle(now.Add(-time.Minute)); err != nil || len(ids) != 0 {
		t.Fatalf("no-op idle transition: %v, %v", ids, err)
	}
	s.UpsertSession(model.Session{ID: "other", StartedAt: now, LastSeenAt: now})
	h = s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"session activity", "session idling"}) {
		t.Fatalf("no-op or unrelated write cleared lifecycle failures: %+v", h)
	}
	if err := s.TouchSession("idle", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	h = s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"session idling"}) {
		t.Fatalf("activity recovery cleared another fault: %+v", h)
	}
	ids, err := s.MarkSessionsIdle(now.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"active", "idle", "other"}) {
		t.Fatalf("recovered idle transitions = %v", ids)
	}
	for _, id := range ids {
		if saved, _ := s.GetSession(id); saved.Status != model.SessionIdle {
			t.Fatalf("returned idle transition was not saved: %+v", saved)
		}
	}
	h = s.WriteHealth()
	if h.Failures != 2 || len(h.Active) != 0 {
		t.Fatalf("idle recovery lost failure history or retained fault: %+v", h)
	}
}

func TestSessionIdlingRejectsPartialUpdate(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for _, id := range []string{"first", "second"} {
		s.UpsertSession(model.Session{ID: id, Status: model.SessionActive, StartedAt: now, LastSeenAt: now})
	}
	if _, err := s.db.Exec(`CREATE TRIGGER skip_idle BEFORE UPDATE ON sessions WHEN OLD.id = 'second' BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.MarkSessionsIdle(now.Add(time.Minute)); err == nil || len(ids) != 0 {
		t.Fatalf("partial idle update returned committed IDs or no error: %v, %v", ids, err)
	}
	for _, id := range []string{"first", "second"} {
		if saved, _ := s.GetSession(id); saved.Status != model.SessionActive {
			t.Fatalf("partial idle update was not rolled back: %+v", saved)
		}
	}
	if h := s.WriteHealth(); h.Failures != 1 || !slices.Equal(h.Active, []string{"session idling"}) {
		t.Fatalf("partial update failure hidden: %+v", h)
	}
}
