package store

import (
	"slices"
	"testing"
	"time"
)

// holdCollectorWrite holds the write mutex and the only database connection
// for hold, as an in-flight collector transaction does.
func holdCollectorWrite(t *testing.T, s *Store, hold time.Duration) (held <-chan struct{}, done <-chan struct{}) {
	t.Helper()
	heldCh, doneCh := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneCh)
		s.mu.Lock()
		defer s.mu.Unlock()
		tx, err := s.db.Begin()
		if err != nil {
			t.Error(err)
			close(heldCh)
			return
		}
		defer tx.Rollback()
		close(heldCh)
		time.Sleep(hold)
	}()
	return heldCh, doneCh
}

func TestGetSessionWaitsForCollectorWrite(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedSessions(t, s, 1)

	held, done := holdCollectorWrite(t, s, 250*time.Millisecond)
	<-held
	got, ok, err := s.GetSession("sess-0")
	if err != nil || !ok || got.ID != "sess-0" {
		t.Fatalf("GetSession during collector write = %+v ok=%v err=%v", got, ok, err)
	}
	if h := s.WriteHealth(); slices.Contains(h.ReadActive, "session lookup") {
		t.Fatalf("waiting read recorded a fault: %+v", h)
	}
	<-done

	held, done = holdCollectorWrite(t, s, 250*time.Millisecond)
	<-held
	if _, _, err := s.GetSessionBounded("sess-0"); err == nil {
		t.Fatal("GetSessionBounded waited past its deadline during a collector write")
	}
	if h := s.WriteHealth(); !slices.Contains(h.ReadActive, "session lookup") {
		t.Fatalf("bounded failure hidden from read health: %+v", h)
	}
	<-done
}

func TestGetSessionReportsFailedReadAsFault(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	seedSessions(t, s, 1)
	s.Close()
	if _, ok, err := s.GetSession("sess-0"); err == nil || ok {
		t.Fatalf("closed store read = ok=%v err=%v", ok, err)
	}
	if h := s.WriteHealth(); !slices.Contains(h.ReadActive, "session lookup") {
		t.Fatalf("failed read hidden from read health: %+v", h)
	}
}
