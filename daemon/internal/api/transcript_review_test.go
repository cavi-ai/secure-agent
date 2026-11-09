package api

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/testvalue"
)

func TestTranscriptReviewHistoricalIncidentProjection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modify  func(*model.Flag, *model.IncidentReport)
		missing bool
		want    model.RiskLevel
	}{
		{name: "single low entropy test candidate", want: model.RiskMedium},
		{name: "missing flag", missing: true, want: model.RiskHigh},
		{name: "aggregated evidence", modify: func(_ *model.Flag, i *model.IncidentReport) { i.AggregateCount = 2 }, want: model.RiskHigh},
		{name: "critical report", modify: func(_ *model.Flag, i *model.IncidentReport) { i.Risk = model.RiskCritical }, want: model.RiskCritical},
		{name: "rotation proof", modify: func(_ *model.Flag, i *model.IncidentReport) {
			i.RotateList = []model.RotateItem{{Risk: model.RiskHigh}}
		}, want: model.RiskHigh},
		{name: "live-looking in tests", modify: func(f *model.Flag, _ *model.IncidentReport) { f.Evidence[1].Sub = testvalue.TestCode }, want: model.RiskHigh},
		{name: "low entropy without context", modify: func(f *model.Flag, _ *model.IncidentReport) { f.Evidence[1].Sub = testvalue.LowEntropy }, want: model.RiskHigh},
		{name: "vague dummy wording", modify: func(f *model.Flag, _ *model.IncidentReport) {
			f.Evidence[1].Sub = testvalue.LowEntropy + "; " + testvalue.DummyWording
		}, want: model.RiskHigh},
		{name: "mixed record", modify: func(f *model.Flag, _ *model.IncidentReport) {
			f.Evidence = append(f.Evidence, model.EvidenceItem{Kind: "text", Text: "additional match"})
		}, want: model.RiskHigh},
		{name: "wrong session", modify: func(f *model.Flag, _ *model.IncidentReport) { f.SessionID = "other" }, want: model.RiskHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := attentionAPI(t, nil)
			at := time.Now().UTC()
			f := model.Flag{ID: "transcript-flag", Rule: "secret-in-transcript", Severity: 2, TS: at, SessionID: "s", Agent: "codex",
				Evidence: []model.EvidenceItem{{Kind: "transcript", Label: "/sessions/s.jsonl", Rule: "db", Sub: "pattern match"},
					{Kind: "test-value", Label: "Looks like a test value", Sub: testvalue.LowEntropy + "; " + testvalue.TestCode}}}
			inc := model.IncidentReport{ID: "historical-transcript", FlagID: f.ID, Rule: f.Rule, Timestamp: at, Agent: f.Agent,
				SessionID: f.SessionID, AggregateCount: 1, Risk: model.RiskHigh, Summary: "Looks like a test value: saved detector evidence"}
			if tc.modify != nil {
				tc.modify(&f, &inc)
			}
			if !tc.missing {
				if _, err := a.store.PutFlag(f); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.store.PutIncident(inc); err != nil {
				t.Fatal(err)
			}
			before, err := a.store.GetIncidentDetail(inc.ID)
			if err != nil {
				t.Fatal(err)
			}
			queued := false
			for _, item := range a.computePosture().Items {
				queued = queued || item.Kind == "incident" && item.ID == inc.ID
			}
			if queued != (tc.want != model.RiskMedium) {
				t.Errorf("queued=%v, want risk %s", queued, tc.want)
			}
			type presentation struct {
				Risk       model.RiskLevel          `json:"risk"`
				Summary    string                   `json:"summary"`
				Assessment *model.FindingAssessment `json:"assessment"`
			}
			for _, path := range []string{"/incidents?id=" + inc.ID, "/incidents", "/snapshot"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				if w.Code != 200 {
					t.Fatalf("%s: status %d", path, w.Code)
				}
				var got presentation
				if strings.HasPrefix(path, "/incidents?id=") {
					var body struct {
						Incident presentation `json:"incident"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					got = body.Incident
				} else if path == "/snapshot" {
					var body struct {
						Incidents []presentation `json:"incidents"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					if len(body.Incidents) != 1 {
						t.Fatalf("snapshot history lost incident: %d", len(body.Incidents))
					}
					got = body.Incidents[0]
				} else {
					var body []presentation
					if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					if len(body) != 1 {
						t.Fatalf("history lost incident: %d", len(body))
					}
					got = body[0]
				}
				if got.Risk != tc.want || got.Summary != inc.Summary {
					t.Errorf("%s: risk=%s summary preserved=%v; want %s", path, got.Risk, got.Summary == inc.Summary, tc.want)
				}
				if tc.want == model.RiskMedium && (got.Assessment == nil || got.Assessment.Risk != "review" || got.Assessment.Reason == "" || len(got.Assessment.Limits) == 0) {
					t.Errorf("%s: missing current review explanation: %+v", path, got.Assessment)
				}
			}
			w := httptest.NewRecorder()
			a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/incidents?id="+inc.ID+"&format=md", nil))
			if w.Code != 200 || !strings.Contains(w.Body.String(), "**Severity Risk**: **"+string(tc.want)+"**") {
				t.Errorf("markdown current risk missing: status=%d", w.Code)
			}
			if tc.want == model.RiskMedium && !strings.Contains(w.Body.String(), "Current assessment") {
				t.Error("markdown omitted current review explanation")
			}
			after, err := a.store.GetIncidentDetail(inc.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("history or workflow mutated: err=%v", err)
			}
		})
	}
}
