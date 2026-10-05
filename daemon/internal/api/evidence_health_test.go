package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestPostureSurfacesBusLoss(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	a.busDrops = func() uint64 { return 7 }
	p := a.computePosture()
	if p.State != "attention" || p.NeedsYou != 0 || p.CoverageCount != 1 {
		t.Fatalf("posture hides lost evidence: %+v", p)
	}
	if p.CoverageItems[0].Kind != "event_loss" || !strings.Contains(p.CoverageItems[0].Detail, "7") {
		t.Fatalf("missing event-loss evidence: %+v", p.CoverageItems)
	}
	if state, _ := checkBus(a.doctorFacts(time.Now())); state != doctorFail {
		t.Fatal("Doctor and posture disagree about bus loss")
	}
}

func TestStorageFailureVisibleInStatusPostureAndDoctor(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	st.Close()
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: time.Now(), Detail: "[REDACTED]"})
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var body struct {
		StorageHealth *struct {
			Failures uint64   `json:"failures"`
			Active   []string `json:"active"`
		} `json:"storage_health"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.StorageHealth == nil || body.StorageHealth.Failures != 1 || len(body.StorageHealth.Active) != 1 {
		t.Fatalf("status hides failed evidence write: %s", w.Body.String())
	}
	p := a.computePosture()
	if p.State != "attention" || p.NeedsYou != 0 || p.CoverageCount != 1 || p.CoverageItems[0].Kind != "storage_loss" {
		t.Fatalf("posture hides storage failure: %+v", p)
	}
	report := a.doctorReport(time.Now())
	for _, c := range report.Checks {
		if c.ID == "storage" && c.State == doctorFail {
			return
		}
	}
	t.Fatalf("Doctor hides storage failure: %+v", report)
}
