package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
)

func newIncidentIngest(t *testing.T) (*eventIngest, persistenceFixture) {
	t.Helper()
	f := newPersistenceFixture(t)
	i := newEventIngest(ingestDeps{
		Store:      f.store,
		Correlator: correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{}),
		Resolver:   session.NewResolver(f.store, f.tagger),
		Tagger:     f.tagger,
	})
	t.Cleanup(i.Stop)
	return i, f
}

func storedFlag(t *testing.T, f persistenceFixture, id string, ts time.Time) model.Flag {
	t.Helper()
	fl := model.Flag{
		ID: id, Rule: "secret-exfil", Severity: 3, TS: ts, PID: 500, SessionID: "sess-1",
		Evidence: []model.EvidenceItem{{Kind: "connect", Label: "evil.example.com:443"}},
	}
	if _, err := f.store.PutFlag(fl); err != nil {
		t.Fatal(err)
	}
	return fl
}

func TestIncidentForCreatesReportForFirstFlag(t *testing.T) {
	i, f := newIncidentIngest(t)
	fl := storedFlag(t, f, "flag-1", time.Now().UTC())
	report, created, err := i.incidentFor(fl)
	if err != nil || !created {
		t.Fatalf("first flag: created=%v err=%v", created, err)
	}
	if report.AggregateCount != 1 || report.SessionID != fl.SessionID || report.Subject != intel.SubjectForFlag(fl) {
		t.Fatalf("report fields: %+v", report)
	}
	saved, err := f.store.GetIncident(report.ID)
	if err != nil || saved == nil || saved.AggregateCount != 1 || saved.SessionID != fl.SessionID || saved.Subject != report.Subject {
		t.Fatalf("report not stored as returned: %+v, %v", saved, err)
	}
}

func TestIncidentForJoinsOpenIncident(t *testing.T) {
	i, f := newIncidentIngest(t)
	now := time.Now().UTC()
	first, created, err := i.incidentFor(storedFlag(t, f, "flag-1", now))
	if err != nil || !created {
		t.Fatalf("first flag: created=%v err=%v", created, err)
	}
	joined, created, err := i.incidentFor(storedFlag(t, f, "flag-2", now.Add(time.Second)))
	if err != nil || created {
		t.Fatalf("second flag: created=%v err=%v", created, err)
	}
	if joined.ID != first.ID || joined.AggregateCount != 2 {
		t.Fatalf("second flag did not join the first incident: %+v vs %+v", joined, first)
	}
	if got := testutil.Read[[]model.IncidentReport](t)(f.store.RecentIncidents(10)); len(got) != 1 {
		t.Fatalf("joined flag created another report: %d incidents", len(got))
	}
}

func TestIncidentForFailedAbsorbPersistsNothing(t *testing.T) {
	i, f := newIncidentIngest(t)
	now := time.Now().UTC()
	first, _, err := i.incidentFor(storedFlag(t, f, "flag-1", now))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `CREATE TRIGGER fail_absorb BEFORE UPDATE ON incidents BEGIN SELECT RAISE(ABORT, 'injected aggregation failure'); END`)
	report, created, err := i.incidentFor(storedFlag(t, f, "flag-2", now.Add(time.Second)))
	var absorbErr absorbError
	if !errors.As(err, &absorbErr) || created || report.ID != "" {
		t.Fatalf("failed absorb: report=%+v created=%v err=%v", report, created, err)
	}
	got := testutil.Read[[]model.IncidentReport](t)(f.store.RecentIncidents(10))
	if len(got) != 1 || got[0].ID != first.ID || got[0].AggregateCount != 1 {
		t.Fatalf("failed absorb changed stored incidents: %+v", got)
	}
}
