package api

import (
	"encoding/json"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResourceReceiptReachesAPIAndSessionExport(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	st.UpsertSession(model.Session{ID: "owned", Harness: "claude", RootPID: 10, RootStartedAt: started.Format(time.RFC3339Nano), StartedAt: started, LastSeenAt: now})
	c := resource.NewController(resource.Policy{Mode: resource.ModePrompt, MaxRSSBytes: 100, Interventions: []resource.InterventionStep{{Action: resource.ActionPause}}}, func(resource.ControlAction) error { return nil })
	if err := c.SetReceiptStore(st); err != nil {
		t.Fatal(err)
	}
	c.Observe(resource.Snapshot{ObservedAt: now, Sessions: []resource.Session{{Key: "family", RootPID: 10, RootStartedAt: started, RSSBytes: 200, Processes: []resource.Process{{PID: 10, StartedAt: started}}}}}, now)
	id := c.Snapshot().Control.Pending[0].ID
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	a.resources = c.Snapshot
	a.resourceControl = c
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/resources/control", strings.NewReader(`{"id":"`+id+`","decision":"apply"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/resources", nil))
	var result resource.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Interventions) != 1 || result.Interventions[0].Status != "applied" || result.Interventions[0].Verification != "pending" {
		t.Fatalf("lost bounded result: %+v", result.Interventions)
	}
	report, ok := st.SessionReport("owned")
	if !ok || len(report.Interventions) != 1 || report.Interventions[0].SessionID != "owned" {
		t.Fatalf("lost session linkage: %+v", report.Interventions)
	}
	md := renderSessionMarkdown(report)
	if !strings.Contains(md, "application: applied · verification: pending") || !strings.Contains(md, "without freeing memory") {
		t.Fatalf("unsupported exported outcome: %s", md)
	}
	other, err := st.RecentInterventions("unrelated", 20)
	if err != nil || len(other) != 0 {
		t.Fatalf("borrowed action: %+v %v", other, err)
	}
}
