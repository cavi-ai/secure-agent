package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestReportEvidencePartialAndPlanGate(t *testing.T) {
	ev := ReportEvidence{
		Events:        ReportSourceEvidence{Available: true},
		Flags:         ReportSourceEvidence{Available: true},
		Reviews:       ReportSourceEvidence{Available: true, AtLimit: true, Limit: 1},
		Incidents:     ReportSourceEvidence{Available: true},
		Interventions: ReportSourceEvidence{Available: true},
	}
	if !ev.Partial() {
		t.Fatal("at-limit reviews are a partial export")
	}
	if ev.PlanCoreUnavailable() {
		t.Fatal("at-limit reviews trip the plan gate")
	}
	ev.Events.Available = false
	if !ev.PlanCoreUnavailable() {
		t.Fatal("unavailable events leave the plan gate closed")
	}
	var missing *ReportEvidence
	if missing.PlanCoreUnavailable() {
		t.Fatal("nil evidence trips the plan gate")
	}
}

func reportJSON(t *testing.T, rep SessionReport) map[string]any {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSessionReportDoesNotTreatFailedEvidenceAsEmpty(t *testing.T) {
	for _, tc := range []struct{ name, sql, source string }{
		{"event query", "ALTER TABLE events RENAME TO unavailable_events", "events"},
		{"event timestamp", "UPDATE events SET ts='invalid' WHERE id=(SELECT MAX(id) FROM events WHERE session_id='s1')", "events"},
		{"event scan", "UPDATE events SET kind=NULL WHERE id=(SELECT MAX(id) FROM events WHERE session_id='s1')", "events"},
		{"flag decode", "UPDATE flags SET evidence='invalid' WHERE session_id='s1'", "flags"},
		{"review decode", "UPDATE finding_reviews SET record_json='null' WHERE session_id='s1'", "reviews"},
		{"review query", "ALTER TABLE finding_reviews RENAME TO unavailable_reviews", "reviews"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := seedReportStore(t, time.Now())
			f := reviewFlag("report-review")
			f.SessionID = "s1"
			if _, err := s.PutFlag(f); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ObserveFindingReview(f, model.AssessFinding(f)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			rep, ok := s.SessionReport("s1")
			if !ok {
				t.Fatal("available session identity was lost")
			}
			evidence, ok := reportJSON(t, rep)["evidence"].(map[string]any)
			if !ok {
				t.Fatal("report has no evidence availability")
			}
			if source, ok := evidence[tc.source].(map[string]any); !ok || source["available"] != false {
				t.Fatalf("failed %s evidence reported available: %+v", tc.source, evidence)
			}
			if tc.source == "events" && (rep.Events != 0 || len(rep.Timeline) != 0) {
				t.Fatal("partial event aggregation escaped")
			}
		})
	}
}

func TestSessionReportDistinguishesBoundedHistoryAndLegacyNullFields(t *testing.T) {
	s := seedReportStore(t, time.Now())
	if _, err := s.db.Exec(`UPDATE events SET path=NULL,remote_host=NULL,detail=NULL WHERE session_id='s1'`); err != nil {
		t.Fatal(err)
	}
	rep, ok := s.SessionReport("s1")
	if !ok || !rep.Evidence.Events.Available || rep.Events != 15 {
		t.Fatalf("legacy optional fields discarded history: %+v", rep.Evidence)
	}
	if _, err := s.db.Exec(`WITH RECURSIVE count(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM count WHERE n<1001)
 INSERT INTO flags (id,rule,severity,ts,pid,session_id,evidence)
 SELECT 'bounded-'||n,'synthetic',1,'2026-10-09T00:00:00Z',1,'s1','[]' FROM count`); err != nil {
		t.Fatal(err)
	}
	rep, ok = s.SessionReport("s1")
	if !ok || !rep.Evidence.Flags.Available || !rep.Evidence.Flags.AtLimit || len(rep.Flags) != rep.Evidence.Flags.Limit {
		t.Fatalf("bounded findings reported complete: %+v", rep.Evidence)
	}
}

func TestSessionReportRetainsReviewDecisionAndRevisionScope(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("export-source")
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	r := onlyReview(t, s)
	if _, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "acknowledge"}); err != nil {
		t.Fatal(err)
	}
	f.Severity++
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(model.Session{ID: "other", Harness: "codex", StartedAt: time.Now(), LastSeenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	other := reviewFlag("other-source")
	other.SessionID = "other"
	if _, err := s.PutFlag(other); err != nil {
		t.Fatal(err)
	}
	rep, ok := s.SessionReport("session")
	if !ok {
		t.Fatal("session not found")
	}
	reviews, ok := reportJSON(t, rep)["reviews"].([]any)
	if !ok || len(reviews) != 1 {
		t.Fatalf("missing or cross-session review history: %+v", reviews)
	}
	exported := reviews[0].(map[string]any)
	decision, ok := exported["decision"].(map[string]any)
	if !ok || decision["action"] != "acknowledge" || decision["revision"] != float64(r.Revision) || exported["revision"].(float64) <= decision["revision"].(float64) {
		t.Fatalf("report erased the old decision or promoted it to changed evidence: %+v", exported)
	}
	if _, err := s.db.Exec(`DELETE FROM flags WHERE id=?`, f.ID); err != nil {
		t.Fatal(err)
	}
	rep, _ = s.SessionReport("session")
	exported = reportJSON(t, rep)["reviews"].([]any)[0].(map[string]any)
	if exported["evidence_available"] != false || exported["decision"] == nil {
		t.Fatal("source expiry erased decision history or invented evidence")
	}
}
