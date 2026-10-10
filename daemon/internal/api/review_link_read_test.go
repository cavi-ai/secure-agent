package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestReviewLinkEnrichmentKeepsCoreFlagsAndBatchFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review-links.db")
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
	at := time.Now().UTC()
	if err := st.UpsertSession(model.Session{ID: "session", Confidence: model.ConfHook}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for i, id := range []string{"bad", "good"} {
		stamp := at.Add(-time.Duration(i) * time.Second)
		f := model.Flag{ID: id, Rule: readConnectRule, Agent: "codex", SessionID: "session", Workspace: "/" + id, Severity: 3, TS: stamp, PID: 42,
			Evidence: []model.EvidenceItem{{Kind: "read", Label: "/" + id + "/credentials", Sub: "sensitive read", PID: 42, TS: stamp.Format(time.RFC3339Nano)}, {Kind: "connect", Label: "203.0.113.5:443", Sub: "egress", PID: 42, TS: stamp.Add(time.Second).Format(time.RFC3339Nano)}}}
		if _, err := st.PutFlag(f); err != nil {
			t.Fatal(err)
		}
		var idsValue string
		if err := db.QueryRow(`SELECT review_id FROM finding_review_members WHERE flag_id=?`, id).Scan(&idsValue); err != nil {
			t.Fatal(err)
		}
		ids[id] = idsValue
	}
	if ids["bad"] == ids["good"] {
		t.Fatal("fixture needs independent reviews")
	}
	if _, err := db.Exec(`CREATE TEMP TABLE original_review AS SELECT * FROM finding_reviews WHERE id=?`, ids["bad"]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM finding_reviews WHERE id=?`, ids["bad"]); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w
	}
	checkFlags := func(flags []model.Flag) {
		t.Helper()
		if len(flags) != 2 || flags[0].ID != "bad" || flags[0].ReviewID != "" || len(flags[0].Evidence) != 2 || flags[1].ReviewID != ids["good"] {
			t.Errorf("bad enrichment erased evidence or retained unusable links: %+v", flags)
		}
	}
	var flags []model.Flag
	if err := json.Unmarshal(request("/flags").Body.Bytes(), &flags); err != nil {
		t.Fatal(err)
	}
	checkFlags(flags)
	if h := st.WriteHealth(); h.ReadFailures == 0 || !slices.Contains(h.ReadActive, "finding reviews") {
		t.Errorf("healthy sibling hid batch failure: %+v", h)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(request("/snapshot").Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	checkFlags(snapshot.Flags)
	if !snapshot.Reviews.Degraded || snapshot.Posture.CoverageCount != 1 || len(snapshot.Posture.CoverageItems) != 1 || !strings.Contains(snapshot.Posture.CoverageItems[0].Detail, "finding reviews") {
		t.Errorf("snapshot hid unavailable review link: %+v", snapshot)
	}
	h := st.WriteHealth()
	if _, err := db.Exec(`INSERT INTO finding_reviews SELECT * FROM original_review`); err != nil {
		t.Fatal(err)
	}
	snapshot = Snapshot{}
	if err := json.Unmarshal(request("/snapshot").Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Reviews.Degraded || snapshot.Posture.CoverageCount != 0 || snapshot.Flags[0].ReviewID != ids["bad"] {
		t.Errorf("snapshot failed to recover: %+v", snapshot)
	}
	if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
		t.Errorf("recovery lost failure history: %+v", got)
	}
}
