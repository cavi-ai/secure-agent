package api

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memorySnapshotRowsStore struct {
	sessions   []model.Session
	events     []event.Event
	sessionErr error
	eventErr   error
	eventReads int
}

func (s *memorySnapshotRowsStore) ListSessionsResult(store.SessionFilter) ([]model.Session, error) {
	return s.sessions, s.sessionErr
}

func (s *memorySnapshotRowsStore) QueryEventsResult(store.EventFilter) ([]event.Event, error) {
	s.eventReads++
	return s.events, s.eventErr
}

func TestSnapshotRowsDoNotExposePartialEvidenceAndRecoverOnNextRead(t *testing.T) {
	for _, source := range []string{"sessions", "events"} {
		t.Run(source, func(t *testing.T) {
			failure := errors.New("source unavailable")
			st := &memorySnapshotRowsStore{
				sessions: []model.Session{{ID: "session"}},
				events:   []event.Event{{SessionID: "session", Detail: "retained event"}},
			}
			if source == "sessions" {
				st.sessionErr = failure
			} else {
				st.eventErr = failure
			}
			sessions, events, err := readSnapshotRows(st)
			if err != failure || sessions != nil || events != nil {
				t.Fatalf("failed source exposed partial evidence: %v %v %v", sessions, events, err)
			}
			if source == "sessions" && st.eventReads != 0 {
				t.Fatal("events read after session source failed")
			}
			st.sessionErr, st.eventErr = nil, nil
			sessions, events, err = readSnapshotRows(st)
			if err != nil || !reflect.DeepEqual(sessions, st.sessions) || !reflect.DeepEqual(events, st.events) {
				t.Fatalf("read did not recover: %v %v %v", sessions, events, err)
			}
		})
	}
}
