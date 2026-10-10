package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestEgressAdvisorReadBatchFailureAndRecovery(t *testing.T) {
	for _, damage := range []string{"corrupt", "unavailable", "stale"} {
		t.Run(damage, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "egress-advice.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			at := time.Now().UTC()
			scope := store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
			for _, host := range []string{"203.0.113.1", "203.0.113.2"} {
				for i := 0; i < 5; i++ {
					st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, SessionID: "s1", Host: host, Protocol: "tcp", Port: 443, At: at.Add(time.Duration(i-4) * time.Hour)})
				}
			}
			a := newTestAPI("", st, nil, nil)
			mux := a.buildMux()
			request := func() []egressEpisodeView {
				t.Helper()
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest("GET", "/egress/episodes", nil))
				if w.Code != 200 {
					t.Fatalf("read: %d %s", w.Code, w.Body.String())
				}
				var response struct {
					Episodes []egressEpisodeView `json:"episodes"`
					Limit    int                 `json:"non_candidate_limit"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if len(response.Episodes) != 2 || response.Limit != 100 {
					t.Fatalf("episode count or limit changed: %+v", response)
				}
				return response.Episodes
			}
			baseline := request()
			for _, row := range baseline {
				if !row.Candidate {
					t.Fatalf("fixture is not recurring: %+v", row)
				}
				if err := st.PutAdvisorVerdict(advisor.EgressSubjectID(row.ID), "egress", model.AdvisorVerdict{Assessment: advisor.EgressEvidenceKey(row.Observed), Rationale: "stored", Confidence: .7, CreatedAt: at}); err != nil {
					t.Fatal(err)
				}
			}
			firstID := advisor.EgressSubjectID(baseline[0].ID)
			switch damage {
			case "corrupt":
				_, err = db.Exec(`UPDATE advisor_verdicts SET created_at='invalid' WHERE subject_id=?`, firstID)
			case "unavailable":
				_, err = db.Exec(`ALTER TABLE advisor_verdicts RENAME TO unavailable_advice`)
			case "stale":
				_, err = db.Exec(`UPDATE advisor_verdicts SET assessment='stale' WHERE subject_id=?`, firstID)
			}
			if err != nil {
				t.Fatal(err)
			}
			rows := request()
			for i, row := range rows {
				core := row
				core.AdvisorInference = nil
				if !reflect.DeepEqual(core, baseline[i]) {
					t.Errorf("core episode or ordering changed: got %+v, want %+v", core, baseline[i])
				}
			}
			if rows[0].AdvisorInference != nil {
				t.Error("invalid or stale advice was returned")
			}
			if damage == "unavailable" {
				if rows[1].AdvisorInference != nil {
					t.Error("unavailable advice was returned")
				}
			} else if v := rows[1].AdvisorInference; v == nil || v.PossiblePurpose != "stored" || v.Confidence != .7 || !v.CreatedAt.Equal(at) {
				t.Errorf("healthy sibling advice lost: %+v", v)
			}
			h := st.WriteHealth()
			if damage == "stale" {
				if h.ReadFailures != 0 || len(h.ReadActive) != 0 {
					t.Errorf("stale evidence counted as storage failure: %+v", h)
				}
			} else if h.ReadFailures != 1 || !slices.Contains(h.ReadActive, "egress advisor verdicts") {
				t.Errorf("egress batch fault lost or counted per row: %+v", h)
			}
			switch damage {
			case "corrupt":
				_, err = db.Exec(`UPDATE advisor_verdicts SET created_at=? WHERE subject_id=?`, at.Format(time.RFC3339Nano), firstID)
			case "unavailable":
				_, err = db.Exec(`ALTER TABLE unavailable_advice RENAME TO advisor_verdicts`)
			case "stale":
				_, err = db.Exec(`UPDATE advisor_verdicts SET assessment=? WHERE subject_id=?`, advisor.EgressEvidenceKey(baseline[0].Observed), firstID)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range request() {
				if row.AdvisorInference == nil || row.AdvisorInference.PossiblePurpose != "stored" {
					t.Errorf("advice did not return after repair: %+v", row)
				}
			}
			if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
				t.Errorf("repair lost failure history: %+v", got)
			}
		})
	}
}
