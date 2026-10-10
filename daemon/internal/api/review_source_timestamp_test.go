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

func TestReviewSourceTimestampRejectsHTTPDecisionAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source-timestamp.db")
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
	f := model.Flag{ID: "timestamp-source", Rule: readConnectRule, Severity: 3, TS: at,
		Evidence: []model.EvidenceItem{{Kind: "read", Label: "/work/credentials", PID: 42, TS: at.Format(time.RFC3339Nano)}, {Kind: "connect", Label: "203.0.113.5:443", PID: 42, TS: at.Add(time.Second).Format(time.RFC3339Nano)}}}
	if _, err := st.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	id, err := st.FindingReviewID(f.ID)
	if err != nil || id == "" {
		t.Fatalf("review fixture: %q %v", id, err)
	}
	body, err := json.Marshal(model.ReviewDecisionRequest{ID: id, Revision: 1, Action: "acknowledge"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE flags SET ts=NULL WHERE id=?`, f.ID); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	request := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("POST", "/reviews/decision", bytes.NewReader(body)))
		if w.Code != want {
			t.Errorf("decision response: %d %s; want %d", w.Code, w.Body.String(), want)
		}
	}
	request(503)
	for _, query := range []string{`SELECT COUNT(*) FROM flags WHERE COALESCE(acknowledged,'')!=''`, `SELECT COUNT(*) FROM finding_review_actions`} {
		var n int
		if err := db.QueryRow(query).Scan(&n); err != nil || n != 0 {
			t.Errorf("failed HTTP decision wrote state: count=%d err=%v", n, err)
		}
	}
	if _, err := db.Exec(`UPDATE flags SET ts=? WHERE id=?`, at.Format(time.RFC3339Nano), f.ID); err != nil {
		t.Fatal(err)
	}
	request(200)
	got, found, err := st.GetFlagResult(f.ID)
	if err != nil || !found || !got.Acknowledged {
		t.Fatalf("repaired decision: %+v found=%v err=%v", got, found, err)
	}
}
