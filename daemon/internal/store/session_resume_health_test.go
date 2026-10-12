package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
)

func TestResumeSessionFailureIsReportedAndRecovers(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	end := now.Add(time.Minute)
	s.UpsertSession(model.Session{ID: "session", Status: model.SessionActive, StartedAt: now, LastSeenAt: now})
	if err := s.EndSession("session", end); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_resume BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'injected resume failure'); END`); err != nil {
		t.Fatal(err)
	}
	if resumed, err := s.ResumeSession("session", end.Add(time.Minute)); err == nil || resumed {
		t.Fatalf("failed resume = %v, %v; want false and an error", resumed, err)
	}
	if saved, ok := testutil.Lookup[model.Session](t)(s.GetSession("session")); !ok || saved.Status != model.SessionEnded || saved.EndedAt == nil {
		t.Fatalf("failed resume changed the session: %+v, %v", saved, ok)
	}
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"session resumes"}) {
		t.Fatalf("session resume failure hidden: %+v", h)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_resume"); err != nil {
		t.Fatal(err)
	}
	if resumed, err := s.ResumeSession("session", end); err != nil || resumed {
		t.Fatalf("resume at the end = %v, %v; want false, nil", resumed, err)
	}
	h = s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"session resumes"}) {
		t.Fatalf("a resume that changed nothing cleared the failure: %+v", h)
	}
	if resumed, err := s.ResumeSession("session", end.Add(time.Minute)); err != nil || !resumed {
		t.Fatalf("resume = %v, %v; want true, nil", resumed, err)
	}
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("resume recovery lost history or retained fault: %+v", h)
	}
}
