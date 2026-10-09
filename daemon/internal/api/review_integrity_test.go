package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestReviewNullRecordIsUnavailableAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review-integrity.db")
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
	f := model.Flag{ID: "source", Rule: readConnectRule, SessionID: "session", Severity: 3, TS: at, PID: 42, Agent: "codex", Evidence: []model.EvidenceItem{{Kind: "read", Label: "/work/credentials", Sub: "sensitive read", PID: 42, TS: at.Format(time.RFC3339Nano)}, {Kind: "connect", Label: "203.0.113.5:443", Sub: "egress", PID: 42, TS: at.Add(time.Second).Format(time.RFC3339Nano)}}}
	if _, err := st.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	var id, raw string
	if err := db.QueryRow("SELECT id,record_json FROM finding_reviews").Scan(&id, &raw); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE finding_reviews SET record_json='null' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	mux := a.buildMux()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/reviews", nil))
	if w.Code != 503 {
		t.Errorf("null review served as available: %d %s", w.Code, w.Body.String())
	}
	readPosture := func() Posture {
		t.Helper()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/posture", nil))
		if w.Code != 200 {
			t.Fatalf("posture: %d %s", w.Code, w.Body.String())
		}
		var p Posture
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := readPosture(); p.State != "attention" || p.CoverageCount != 1 {
		t.Errorf("null review produced healthy posture: %+v", p)
	}
	if _, err := db.Exec("UPDATE finding_reviews SET record_json=? WHERE id=?", raw, id); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/reviews", nil))
	if w.Code != 200 {
		t.Errorf("review recovery: %d %s", w.Code, w.Body.String())
	}
	if p := readPosture(); p.State != "all-clear" || p.CoverageCount != 0 {
		t.Errorf("posture recovery: %+v", p)
	}
}
