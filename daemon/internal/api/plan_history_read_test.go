package api

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestPlanHistoryReadFailureRejectsGenerationAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutIncident(model.IncidentReport{ID: "i1", Rule: "rule", Agent: "codex", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutFlag(model.Flag{ID: "f1", Rule: "rule", Agent: "codex", TS: time.Now(), Severity: 3}); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	rec := &planRecorder{ready: true, pending: map[string]bool{}}
	a.plan = rec.funcs()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("ALTER TABLE flags RENAME TO unavailable_flags"); err != nil {
		t.Fatal(err)
	}
	// The incident remains readable; only its rule history is unavailable.
	if code, _ := planCall(t, a, http.MethodGet, "incident:i1"); code != http.StatusOK {
		t.Fatalf("stored plan view: %d", code)
	}
	if code, _ := planCall(t, a, http.MethodPost, "incident:i1"); code != http.StatusServiceUnavailable {
		t.Errorf("unavailable history: %d, want 503", code)
	}
	if len(rec.reqs) != 0 {
		t.Errorf("enqueued %d plans with unavailable history", len(rec.reqs))
	}
	if _, err := db.Exec("ALTER TABLE unavailable_flags RENAME TO flags"); err != nil {
		t.Fatal(err)
	}
	if code, _ := planCall(t, a, http.MethodPost, "incident:i1"); code != http.StatusAccepted {
		t.Fatalf("recovered history: %d", code)
	}
	if len(rec.reqs) != 1 || !strings.Contains(strings.Join(rec.reqs[0].Context, "\n"), "history: rule rule fired 1 times for this agent in the last 7 days, 1 in 30 days") {
		t.Fatalf("recovered requests: %+v", rec.reqs)
	}
}
