package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestPostureRetainsReviewReadFailureAfterHealthyLookup(t *testing.T) {
	for _, failure := range []string{"list", "detail", "incident detail"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reviews.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Now().UTC()
			if err := st.UpsertSession(model.Session{ID: "session", Confidence: model.ConfHook, StartedAt: now, LastSeenAt: now}); err != nil {
				t.Fatal(err)
			}
			var badID, goodID, badJSON string
			for i, id := range []string{"bad", "good"} {
				at := now.Add(-time.Duration(i) * time.Second)
				f := model.Flag{ID: id, Rule: readConnectRule, Workspace: "/" + id, SessionID: "session", Severity: 3, TS: at, PID: 42, Agent: "codex", Evidence: []model.EvidenceItem{{Kind: "read", Label: "/" + id + "/credentials", Sub: "sensitive read", PID: 42, TS: at.Format(time.RFC3339Nano)}, {Kind: "connect", Label: "203.0.113.5:443", Sub: "egress", PID: 42, TS: at.Add(time.Second).Format(time.RFC3339Nano)}}}
				if _, err := st.PutFlag(f); err != nil {
					t.Fatal(err)
				}
				r, err := st.ObserveFindingReview(f, model.AssessFinding(f))
				if err != nil {
					t.Fatal(err)
				}
				// Valid reviewed records leave the unreviewed list, while source
				// flags remain available to exercise the narrower lookup.
				r.ReviewState, r.Assessment.ReviewState = "reviewed", "reviewed"
				raw, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("UPDATE finding_reviews SET state='reviewed',record_json=? WHERE id=?", string(raw), r.ID); err != nil {
					t.Fatal(err)
				}
				if id == "bad" {
					badID, badJSON = r.ID, string(raw)
				} else {
					goodID = r.ID
				}
			}
			if badID == "" || goodID == "" || badID == goodID {
				t.Fatal("fixture requires two independent reviews")
			}
			if failure == "incident detail" {
				if _, err := db.Exec("UPDATE flags SET acknowledged=?", now.Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
				for i, id := range []string{"bad", "good"} {
					if err := st.PutIncident(model.IncidentReport{ID: "incident-" + id, FlagID: id, Risk: model.RiskCritical, Timestamp: now.Add(-time.Duration(i) * time.Second)}); err != nil {
						t.Fatal(err)
					}
				}
			}
			state := "reviewed"
			if failure == "list" {
				state = "unreviewed"
			}
			if _, err := db.Exec("UPDATE finding_reviews SET state=?,record_json='invalid' WHERE id=?", state, badID); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			read := func() Posture {
				t.Helper()
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/posture", nil))
				if w.Code != 200 {
					t.Fatalf("posture: %d %s", w.Code, w.Body.String())
				}
				var p Posture
				if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
					t.Fatal(err)
				}
				return p
			}
			p := read()
			if p.CoverageCount != 1 || len(p.CoverageItems) != 1 || p.CoverageItems[0].Kind != "storage_read_failure" || !strings.Contains(p.CoverageItems[0].Detail, "finding reviews") {
				t.Errorf("later healthy lookup hid %s failure: %+v", failure, p)
			}
			if failure == "incident detail" && (p.State != "critical" || p.NeedsYou != 1 || len(p.Items) != 1 || p.Items[0].ID != "incident-bad") {
				t.Errorf("unavailable review erased known critical incident: %+v", p)
			}
			h := st.WriteHealth()
			if h.ReadFailures == 0 || (failure != "list" && len(h.ReadActive) != 0) {
				t.Errorf("fixture must clear runtime fault while preserving calculation failure: %+v", h)
			}
			if _, err := db.Exec("UPDATE finding_reviews SET state='reviewed',record_json=? WHERE id=?", badJSON, badID); err != nil {
				t.Fatal(err)
			}
			p = read()
			if p.State != "all-clear" || p.NeedsYou != 0 || p.CoverageCount != 0 {
				t.Errorf("first healthy calculation did not recover: %+v", p)
			}
			if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
				t.Errorf("recovery lost failure history: %+v", got)
			}
		})
	}
}
