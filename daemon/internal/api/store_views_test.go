package api

import (
	"errors"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryReviewStore struct {
	calls int
	err   error
}

func (s *memoryReviewStore) ListFindingReviewsState(string, int, string) (store.ReviewPage, error) {
	return store.ReviewPage{}, nil
}
func (s *memoryReviewStore) FindingReviewID(string) (string, error) {
	s.calls++
	return "review", s.err
}
func (s *memoryReviewStore) GetFindingReview(string) (model.ReviewRecord, bool, error) {
	return model.ReviewRecord{ID: "review"}, true, nil
}

func TestFindingReviewViewPreservesFailuresWithinOnePass(t *testing.T) {
	s := &memoryReviewStore{err: errors.New("read failed")}
	v := newFindingReviewView(s)
	_, _, first := v.ForFlag("flag")
	s.err = nil
	_, _, second := v.ForFlag("flag")
	if first == nil || second != first || s.calls != 1 {
		t.Fatalf("read failure lost: %v %v %d", first, second, s.calls)
	}
	if r, ok, err := newFindingReviewView(s).ForFlag("flag"); err != nil || !ok || r.ID != "review" {
		t.Fatalf("new pass did not recover: %+v %v %v", r, ok, err)
	}
}

type memoryTimelineStore struct {
	events []event.Event
	err    error
}

func (s memoryTimelineStore) QueryEventsResult(store.EventFilter) ([]event.Event, error) {
	return append([]event.Event(nil), s.events...), s.err
}

func TestSessionTimelineViewOrdersEvidenceAndReturnsReadErrors(t *testing.T) {
	s := memoryTimelineStore{events: []event.Event{{Detail: "new"}, {Detail: "old"}}}
	rows, err := sessionTimeline(s, "session", 2)
	if err != nil || len(rows) != 2 || rows[0].Detail != "old" {
		t.Fatalf("timeline: %+v %v", rows, err)
	}
	s.err = errors.New("unavailable")
	if _, err := sessionTimeline(s, "session", 2); err != s.err {
		t.Fatalf("read error hidden: %v", err)
	}
}
