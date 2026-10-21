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

func TestSessionOutcomeDoesNotWaitForCollectorMutex(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now()
	if err := s.UpsertSession(model.Session{ID: "owned", Harness: "codex", StartedAt: at, LastSeenAt: at, Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	done := make(chan error, 1)
	go func() {
		history, found, err := s.SessionOutcomeContext(context.Background(), "owned")
		if err == nil && (!found || !history.Evidence.Guards.Available || !history.Evidence.Reviews.Available || !history.Evidence.Incidents.Available || !history.Evidence.Interventions.Available) {
			err = errors.New("retained receipt sources unavailable")
		}
		done <- err
	}()
	select {
	case err := <-done:
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		s.mu.Unlock()
		<-done
		t.Fatal("receipt history waited for the ingestion mutex")
	}
}

func TestReceiptSourcesHonorCancellationAfterIdentity(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now()
	if err := s.UpsertSession(model.Session{ID: "owned", Harness: "codex", StartedAt: at, LastSeenAt: at, Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.getSessionContext(context.Background(), "owned"); err != nil || !found {
		t.Fatalf("identity: found=%v error=%v", found, err)
	}
	for _, tc := range []struct {
		name string
		read func(receiptReader) error
	}{
		{"guards", func(r receiptReader) error { _, err := r.GuardDecisionHistory("owned", 200); return err }},
		{"reviews", func(r receiptReader) error { _, err := r.ListSessionFindingReviews("owned"); return err }},
		{"interventions", func(r receiptReader) error { _, err := r.RecentInterventions("owned", 200); return err }},
		{"incidents", func(r receiptReader) error { _, err := r.SessionIncidents("owned"); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := tc.read(receiptReader{s, contextRows{ctx, tx}}); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled receipt read: %v", err)
			}
		})
	}
}
