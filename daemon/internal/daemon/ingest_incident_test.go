package daemon

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
	"github.com/cavi-ai/secure-agent/daemon/internal/testvalue"
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

func TestTranscriptIncidentRetainsStrongestRisk(t *testing.T) {
	i, fixture := newIncidentIngest(t)
	at := time.Now().UTC()
	var incidentID string
	for n, tc := range []struct {
		layer, signals string
		severity       int
		want           model.RiskLevel
	}{
		{"pattern", testvalue.LowEntropy + "; " + testvalue.TestCode, 2, model.RiskMedium},
		{"pattern", testvalue.TestCode, 2, model.RiskHigh},
		{"fingerprint", "", 3, model.RiskCritical},
		{"pattern", testvalue.LowEntropy + "; " + testvalue.TestCode, 2, model.RiskCritical},
	} {
		fl := model.Flag{ID: fmt.Sprintf("transcript-%d", n), Rule: "secret-in-transcript", Severity: tc.severity,
			TS: at.Add(time.Duration(n) * time.Second), Agent: "codex", SessionID: "s",
			Evidence: []model.EvidenceItem{{Kind: "transcript", Label: "/sessions/s.jsonl", Sub: tc.layer + " match", Rule: "db"},
				{Kind: "test-value", Sub: tc.signals}}}
		if _, err := fixture.store.PutFlag(fl); err != nil {
			t.Fatal(err)
		}
		report, created, err := i.incidentFor(fl)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			incidentID = report.ID
		}
		if report.ID != incidentID || created != (n == 0) || report.AggregateCount != n+1 || report.Risk != tc.want {
			t.Fatalf("match %d: risk=%s count=%d created=%v same incident=%v; want risk=%s", n, report.Risk, report.AggregateCount, created, report.ID == incidentID, tc.want)
		}
		saved, err := fixture.store.GetIncident(incidentID)
		if err != nil || saved.Risk != tc.want {
			t.Fatalf("persisted aggregate risk=%v err=%v", saved, err)
		}
		var indexedRisk model.RiskLevel
		if err := fixture.db.QueryRow(`SELECT risk FROM incidents WHERE id=?`, incidentID).Scan(&indexedRisk); err != nil || indexedRisk != tc.want {
			t.Fatalf("session-memory risk=%s, want %s; err=%v", indexedRisk, tc.want, err)
		}
	}
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
