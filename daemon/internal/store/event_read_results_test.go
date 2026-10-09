package store

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestEventReadResultsDiscardPartialRowsAndRecover(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, sid := range []string{"bad", "good"} {
		if _, err := s.PutEvent(event.Event{Kind: event.KindToolCall, TS: time.Now(), SessionID: sid}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE events SET pid='invalid' WHERE session_id='bad'"); err != nil {
		t.Fatal(err)
	}
	got, err := s.QueryEventsResult(EventFilter{})
	if err == nil || got != nil {
		t.Fatalf("partial rows returned: %+v, %v", got, err)
	}
	h := s.WriteHealth()
	if h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"events"}) || h.Failures != 0 {
		t.Fatalf("read failure misclassified: %+v", h)
	}
	if _, err := s.db.Exec("UPDATE events SET pid=0 WHERE session_id='bad'"); err != nil {
		t.Fatal(err)
	}
	got, err = s.QueryEventsResult(EventFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("read did not recover: %+v, %v", got, err)
	}
	h = s.WriteHealth()
	if h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Fatalf("recovery erased failures or retained fault: %+v", h)
	}
	got, err = s.QueryEventsResult(EventFilter{SessionID: "empty"})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("successful empty read: %+v, %v", got, err)
	}
}

func TestEventCursorFailureDiscardsEarlierValidRows(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Newest-first traversal reads the valid PID 1 row before the expression
	// fails in SQLite while advancing to PID 2. No driver stub is involved.
	for _, pid := range []int32{2, 1} {
		if _, err := s.PutEvent(event.Event{Kind: event.KindToolCall, PID: pid, TS: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	q, args := eventQuery(EventFilter{})
	q = strings.Replace(q, " detail,", " CASE WHEN pid=2 THEN json_extract('invalid','$') ELSE detail END,", 1)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := scanEventsResult(rows)
	if err == nil || got != nil {
		t.Fatalf("cursor failure returned partial data: %+v, %v", got, err)
	}
}
