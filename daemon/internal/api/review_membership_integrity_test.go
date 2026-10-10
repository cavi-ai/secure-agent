package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestForeignReviewMembershipRejectsHTTPDecisionAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "membership.db")
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
	if err := st.UpsertSession(model.Session{ID: "session", Confidence: model.ConfHook}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, id := range []string{"first", "second"} {
		at := time.Now().UTC()
		f := model.Flag{ID: id, Rule: readConnectRule, Agent: "codex", PID: 42, SessionID: "session", Workspace: "/work", Severity: 3, TS: at,
			Evidence: []model.EvidenceItem{{Kind: "read", Label: "/work/" + id, Sub: "sensitive read", PID: 42, TS: at.Format(time.RFC3339Nano)}, {Kind: "connect", Label: "203.0.113.5:443", Sub: "egress", PID: 42, TS: at.Add(time.Second).Format(time.RFC3339Nano)}}}
		if _, err := st.PutFlag(f); err != nil {
			t.Fatal(err)
		}
		var reviewID string
		if err := db.QueryRow(`SELECT review_id FROM finding_review_members WHERE flag_id=?`, id).Scan(&reviewID); err != nil {
			t.Fatal(err)
		}
		ids[id] = reviewID
	}
	if _, err := db.Exec(`UPDATE finding_review_members SET review_id=? WHERE flag_id='second'`, ids["first"]); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	body, err := json.Marshal(model.ReviewDecisionRequest{ID: ids["first"], Revision: 1, Action: "acknowledge"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body []byte, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	request("GET", "/reviews", nil, 503)
	var flags []model.Flag
	if err := json.Unmarshal(request("GET", "/flags", nil, 200).Body.Bytes(), &flags); err != nil {
		t.Fatal(err)
	}
	if len(flags) != 2 || flags[0].ID != "second" || flags[0].ReviewID != "" || len(flags[0].Evidence) != 2 || flags[1].ReviewID != ids["first"] {
		t.Fatalf("foreign linkage hid core evidence or survived: %+v", flags)
	}
	request("POST", "/reviews/decision", body, 409)
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM flags WHERE COALESCE(acknowledged,'')!=''`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected HTTP decision wrote flags: %d %v", count, err)
	}
	h := st.WriteHealth()
	if h.ReadFailures == 0 {
		t.Fatal("review membership failure was not recorded")
	}
	if _, err := db.Exec(`UPDATE finding_review_members SET review_id=? WHERE flag_id='second'`, ids["second"]); err != nil {
		t.Fatal(err)
	}
	request("GET", "/reviews", nil, 200)
	request("POST", "/reviews/decision", body, 200)
	first, found, err := st.GetFlagResult("first")
	if err != nil || !found || !first.Acknowledged {
		t.Fatalf("valid decision failed after repair: %+v %v", first, err)
	}
	second, found, err := st.GetFlagResult("second")
	if err != nil || !found || second.Acknowledged {
		t.Fatalf("valid decision crossed repaired membership: %+v %v", second, err)
	}
	if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
		t.Errorf("membership recovery lost read history: %+v", got)
	}
}
