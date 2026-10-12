package store

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type memoryReportReader struct {
	session                        model.Session
	found                          bool
	identityErr, eventErr, flagErr error
	events                         []event.Event
	flags                          []model.Flag
	history                        SessionOutcomeHistory
	reads                          []string
	filter                         FlagFilter
}

func (r *memoryReportReader) GetSessionBounded(id string) (model.Session, bool, error) {
	r.reads = append(r.reads, "session:"+id)
	return r.session, r.found, r.identityErr
}

func (r *memoryReportReader) sessionEventsOldestFirst(id string) ([]event.Event, error) {
	r.reads = append(r.reads, "events:"+id)
	return r.events, r.eventErr
}

func (r *memoryReportReader) QueryFlagsResult(filter FlagFilter) ([]model.Flag, error) {
	r.reads = append(r.reads, "flags:"+filter.SessionID)
	r.filter = filter
	return r.flags, r.flagErr
}

func (r *memoryReportReader) SessionOutcomes(id string) SessionOutcomeHistory {
	r.reads = append(r.reads, "outcomes:"+id)
	return r.history
}

func TestReportReaderStopsAtUnavailableIdentity(t *testing.T) {
	failed := errors.New("identity unavailable")
	for _, readErr := range []error{nil, failed} {
		r := &memoryReportReader{identityErr: readErr}
		rep, found, err := readSessionReport(r, "owned")
		if found || !errors.Is(err, readErr) || !reflect.DeepEqual(rep, SessionReport{}) || !reflect.DeepEqual(r.reads, []string{"session:owned"}) {
			t.Fatalf("identity result leaked evidence: %+v, %v, %v, reads=%v", rep, found, err, r.reads)
		}
	}
}

func TestReportReaderIndependentEvidenceAndRecovery(t *testing.T) {
	failed := errors.New("source unavailable")
	for _, source := range []string{"events", "flags", "both"} {
		t.Run(source, func(t *testing.T) {
			start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			ended := start.Add(time.Minute)
			r := &memoryReportReader{
				session: model.Session{ID: "owned", StartedAt: start, EndedAt: &ended, LastSeenAt: start.Add(time.Hour)}, found: true,
				events: []event.Event{{Kind: event.KindModelCall, TS: start, Model: "model", TokensIn: 7, TokensOut: 3, CostUSD: 0.5}},
				flags:  []model.Flag{{ID: "finding"}},
				history: SessionOutcomeHistory{
					Reviews: []model.ReviewRecord{{ID: "review"}}, Incidents: []model.IncidentReport{}, Interventions: []model.InterventionReceipt{{ID: "control", Status: "failed"}},
					Evidence: SessionOutcomeEvidence{Reviews: ReportSourceEvidence{Available: true, AtLimit: true, Limit: 100}, Incidents: ReportSourceEvidence{Limit: 100}, Interventions: ReportSourceEvidence{Available: true, Limit: 200}},
				},
			}
			if source != "flags" {
				r.eventErr = failed
			}
			if source != "events" {
				r.flagErr = failed
			}
			rep, found, err := readSessionReport(r, "owned")
			if err != nil || !found || rep.DurationS != 60 || rep.Evidence == nil || !rep.Evidence.Partial() || !rep.Evidence.PlanCoreUnavailable() {
				t.Fatalf("partial report lost identity or evidence state: %+v, %v, %v", rep, found, err)
			}
			if rep.Evidence.Events.Available != (r.eventErr == nil) || rep.Evidence.Flags.Available != (r.flagErr == nil) {
				t.Fatalf("source availability changed: %+v", rep.Evidence)
			}
			if r.eventErr != nil && (rep.Events != 0 || rep.TokensIn != 0 || rep.CostUSD != 0 || len(rep.Timeline) != 0 || len(rep.Models) != 0) {
				t.Fatalf("failed source published partial activity: %+v", rep)
			}
			if r.flagErr != nil && (rep.Flags == nil || len(rep.Flags) != 0) {
				t.Fatalf("failed source published partial flags: %+v", rep.Flags)
			}
			if len(rep.Reviews) != 1 || rep.Reviews[0].ID != "review" || rep.Evidence.Reviews != r.history.Evidence.Reviews || rep.IncidentsAvailable || !rep.InterventionsAvailable || rep.Interventions[0].Status != "failed" {
				t.Fatalf("independent outcome facts changed: %+v", rep)
			}
			if !reflect.DeepEqual(r.reads, []string{"session:owned", "events:owned", "flags:owned", "outcomes:owned"}) || r.filter != (FlagFilter{SessionID: "owned", Limit: 1000}) {
				t.Fatalf("report query scope changed: %v, %+v", r.reads, r.filter)
			}
			r.eventErr, r.flagErr = nil, nil
			rep, found, err = readSessionReport(r, "owned")
			if err != nil || !found || rep.Events != 1 || rep.TokensIn != 7 || rep.TokensOut != 3 || rep.CostUSD != 0.5 || len(rep.Flags) != 1 || rep.Flags[0].ID != "finding" || rep.Evidence.PlanCoreUnavailable() {
				t.Fatalf("report failed to recover source facts: %+v, %v, %v", rep, found, err)
			}
		})
	}
}

func TestReportReaderRejectsOverflowBeforeLaterReads(t *testing.T) {
	r := &memoryReportReader{found: true, session: model.Session{ID: "owned"}, events: []event.Event{
		{Kind: event.KindModelCall, TokensIn: math.MaxInt64}, {Kind: event.KindModelCall, TokensIn: 1},
	}}
	rep, found, err := readSessionReport(r, "owned")
	if err == nil || found || !reflect.DeepEqual(rep, SessionReport{}) || !reflect.DeepEqual(r.reads, []string{"session:owned", "events:owned"}) {
		t.Fatalf("overflow published totals or queried later evidence: %+v, %v, %v, reads=%v", rep, found, err, r.reads)
	}
}
