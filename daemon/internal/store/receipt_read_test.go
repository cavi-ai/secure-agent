package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionOutcomeWaitsForConnectionWithinReadBudget(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now()
	if err := s.UpsertSession(model.Session{ID: "owned", Harness: "codex", StartedAt: at, LastSeenAt: at, Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_, found, err := s.SessionOutcome("owned")
		if err == nil && !found {
			err = context.Canceled
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("retained outcome failed before a transiently busy connection was released: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retained outcome did not recover: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retained outcome read did not finish")
	}
}

func TestInterventionHistoryDoesNotWaitForCollectorMutex(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := s.RecentInterventions("", 10); done <- err }()
	select {
	case err := <-done:
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		s.mu.Unlock()
		<-done
		t.Fatal("receipt read waited on unrelated collector work")
	}
}

func TestSessionOutcomeHonorsRequestCancellation(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, found, err := s.SessionOutcomeContext(ctx, "owned")
	if found || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled identity read: found=%v error=%v", found, err)
	}
}
