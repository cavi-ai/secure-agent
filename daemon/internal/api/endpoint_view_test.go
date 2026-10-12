package api

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryEndpointEvidence struct {
	events     []event.Event
	eventErr   error
	sessions   map[string]model.Session
	sessionErr map[string]error
	filter     store.EventFilter
	looked     []string
}

func (s *memoryEndpointEvidence) QueryEventsResult(f store.EventFilter) ([]event.Event, error) {
	s.filter = f
	return s.events, s.eventErr
}
func (s *memoryEndpointEvidence) GetSessionBounded(id string) (model.Session, bool, error) {
	s.looked = append(s.looked, id)
	if err := s.sessionErr[id]; err != nil {
		return model.Session{}, false, err
	}
	sess, ok := s.sessions[id]
	return sess, ok, nil
}

func TestEndpointConnectionsDistinctSessionsInOrder(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	st := &memoryEndpointEvidence{
		events:   []event.Event{{SessionID: "s2"}, {}, {SessionID: "s2"}, {SessionID: "gone"}, {SessionID: "s1"}},
		sessions: map[string]model.Session{"s1": {ID: "s1"}, "s2": {ID: "s2"}},
	}
	evs, sessions, err := endpointConnections(st, "api.example", now)
	if err != nil || len(evs) != 5 {
		t.Fatalf("events = %d, %v", len(evs), err)
	}
	if want := (store.EventFilter{RemoteHost: "api.example", Since: "2026-10-05T12:00:00Z", Limit: 50}); !reflect.DeepEqual(st.filter, want) {
		t.Fatalf("filter = %+v, want %+v", st.filter, want)
	}
	if !slices.Equal(st.looked, []string{"s2", "gone", "s1"}) {
		t.Fatalf("session lookups = %v, want each distinct session once", st.looked)
	}
	if !reflect.DeepEqual(sessions, []model.Session{{ID: "s2"}, {ID: "s1"}}) {
		t.Fatalf("sessions = %+v, want first-seen order without missing ones", sessions)
	}
}

func TestEndpointConnectionsRejectFailedReadsAndEncodeEmpty(t *testing.T) {
	failed := errors.New("unavailable")
	if _, _, err := endpointConnections(&memoryEndpointEvidence{eventErr: failed}, "h", time.Now()); err != errEndpointEvents || err.Error() != "endpoint events unavailable" {
		t.Fatalf("event failure = %v", err)
	}
	st := &memoryEndpointEvidence{events: []event.Event{{SessionID: "s1"}, {SessionID: "s2"}},
		sessions: map[string]model.Session{"s1": {ID: "s1"}}, sessionErr: map[string]error{"s2": failed}}
	if evs, sessions, err := endpointConnections(st, "h", time.Now()); err != errEndpointSessions || err.Error() != "endpoint sessions unavailable" || evs != nil || sessions != nil {
		t.Fatalf("session failure = %v, %v, %v", evs, sessions, err)
	}
	evs, sessions, err := endpointConnections(&memoryEndpointEvidence{}, "h", time.Now())
	if err != nil || evs == nil || sessions == nil || len(evs)+len(sessions) != 0 {
		t.Fatalf("empty history must encode as []: %#v %#v %v", evs, sessions, err)
	}
}

func TestHostAdviceBatchKeepsValidVerdictsOnFailure(t *testing.T) {
	rows := []UninspectedEndpoint{{Agent: "codex", Host: "a.example"}, {Agent: "claude", Host: "b.example"}}
	r := &memoryAdvisorVerdicts{err: errors.New("advice unavailable"), verdicts: map[string]model.AdvisorVerdict{
		"host:claude|b.example": {Assessment: "expected", Rationale: "Known API"},
	}}
	attachHostAdvice(r, rows)
	if r.reads != 1 || r.kind != "host" || !slices.Equal(r.ids, []string{"host:codex|a.example", "host:claude|b.example"}) {
		t.Fatalf("advice batch: %+v", r)
	}
	if rows[0].Assessment != "" || rows[1].Assessment != "expected" || rows[1].Rationale != "Known API" {
		t.Fatalf("advice attached to the wrong rows: %+v", rows)
	}
}
