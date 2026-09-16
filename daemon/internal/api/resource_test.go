package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

func TestResourcesEndpoint(t *testing.T) {
	a := New("", testStore(t), nil, func() Status { return Status{Running: true} })

	unwired := httptest.NewRecorder()
	a.buildMux().ServeHTTP(unwired, httptest.NewRequest(http.MethodGet, "/resources", nil))
	if unwired.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired GET code=%d want 503", unwired.Code)
	}

	want := resource.Snapshot{
		ObservedAt: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		Host: &resource.HostSnapshot{TotalMemoryBytes: 16 << 30, AvailableMemoryBytes: 4 << 30,
			MemoryPressure: "normal", ThermalState: "nominal", HeadroomScore: 25, Capacity: "constrained"},
		RSSBytes: 300, CPUPercent: 75, ProcessCount: 2, SessionCount: 1,
		Episodes: []resource.Episode{},
		Sessions: []resource.Session{{
			Key: "10:100", Name: "claude", RootPID: 10, RSSBytes: 300, CPUPercent: 75, ProcessCount: 2,
			Processes: []resource.Process{{PID: 10, RSSBytes: 200}, {PID: 11, PPID: 10, RSSBytes: 100}},
			Samples:   []resource.Sample{{At: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC), RSSBytes: 300, CPUPercent: 75}},
			Diagnoses: []resource.Diagnosis{{Code: "heavy-cpu", Severity: "critical", Summary: "busy", Evidence: []string{"CPU 75"}, Threshold: "test", Confidence: "high"}},
		}},
	}
	a.SetResources(func() resource.Snapshot { return want })

	method := httptest.NewRecorder()
	a.buildMux().ServeHTTP(method, httptest.NewRequest(http.MethodPost, "/resources", nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code=%d want 405", method.Code)
	}

	response := httptest.NewRecorder()
	a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/resources", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET code=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"episodes":[]`) {
		t.Fatalf("empty episodes must encode as []: %s", response.Body.String())
	}
	var got resource.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestResourcesEndpointIncludesPressureEpisodes(t *testing.T) {
	st := testStore(t)
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	if err := st.PutResourceEpisode(resource.Episode{CapturedAt: now, Severity: "critical",
		Session: resource.Session{Key: "10:100", RootPID: 10, RSSBytes: 5 << 30}}); err != nil {
		t.Fatal(err)
	}
	a := New("", st, nil, func() Status { return Status{Running: true} })
	a.SetResources(func() resource.Snapshot { return resource.Snapshot{ObservedAt: now} })

	response := httptest.NewRecorder()
	a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/resources", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	var got resource.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Episodes) != 1 || got.Episodes[0].Session.Key != "10:100" {
		t.Fatalf("episodes=%+v", got.Episodes)
	}
}

func TestResourcePolicyEndpointPersistsBeforeApply(t *testing.T) {
	st := testStore(t)
	a := New("", st, nil, func() Status { return Status{Running: true} })
	control := resource.NewController(resource.Policy{Mode: resource.ModeObserve, MaxRSSBytes: 100}, nil)
	a.SetResourceControl(control)
	var persisted config.ResourceControlConfig
	a.SetResourcePolicyUpdater(func(next config.ResourceControlConfig) error {
		persisted = next
		control.SetPolicySet(testResourcePolicySet(next))
		return nil
	})
	body := strings.NewReader(`{"mode":"prompt","max_rss_mb":2048,"max_cpu_percent":150,"sustain_seconds":30,"cooldown_seconds":300,"interventions":[{"action":"notify","after_seconds":0},{"action":"pause","after_seconds":60}],"workspace_overrides":[{"cwd_prefix":"/work/app","mode":"terminate","max_rss_mb":4096,"max_cpu_percent":200,"sustain_seconds":60,"cooldown_seconds":600}]}`)
	response := httptest.NewRecorder()
	a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/resources/policy", body))
	if response.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	if persisted.Mode != "prompt" || len(persisted.Interventions) != 2 || persisted.Interventions[1].Action != "pause" || len(persisted.WorkspaceOverrides) != 1 {
		t.Fatalf("persisted=%+v", persisted)
	}
	if got := control.Snapshot().Control; got.Mode != resource.ModePrompt || len(got.Interventions) != 2 || len(got.WorkspaceOverrides) != 1 {
		t.Fatalf("active=%+v", got)
	}
	if audits := st.RecentAudit(5); len(audits) != 1 || audits[0].Action != "resource-policy-update" {
		t.Fatalf("audit=%+v", audits)
	}
}

func testResourcePolicySet(c config.ResourceControlConfig) resource.PolicySet {
	set := resource.PolicySet{Default: resource.Policy{Mode: resource.ControlMode(c.Mode), MaxRSSBytes: c.MaxRSSMB * 1024 * 1024,
		MaxCPUPercent: c.MaxCPUPercent, Sustain: time.Duration(c.SustainSeconds) * time.Second, Cooldown: time.Duration(c.CooldownSeconds) * time.Second,
		Interventions: testResourceInterventions(c.Interventions)}}
	for _, override := range c.WorkspaceOverrides {
		set.WorkspaceOverrides = append(set.WorkspaceOverrides, resource.WorkspacePolicy{Path: override.CwdPrefix, Policy: resource.Policy{
			Mode: resource.ControlMode(override.Mode), MaxRSSBytes: override.MaxRSSMB * 1024 * 1024,
			MaxCPUPercent: override.MaxCPUPercent, Sustain: time.Duration(override.SustainSeconds) * time.Second,
			Cooldown: time.Duration(override.CooldownSeconds) * time.Second, Interventions: testResourceInterventions(override.Interventions),
		}})
	}
	return set
}

func testResourceInterventions(steps []config.ResourceInterventionConfig) []resource.InterventionStep {
	out := make([]resource.InterventionStep, 0, len(steps))
	for _, step := range steps {
		out = append(out, resource.InterventionStep{Action: resource.InterventionAction(step.Action), After: time.Duration(step.AfterSeconds) * time.Second, Nice: step.Nice})
	}
	return out
}

func TestResourcePolicyEndpointLeavesActivePolicyOnWriteFailure(t *testing.T) {
	a := New("", testStore(t), nil, func() Status { return Status{Running: true} })
	control := resource.NewController(resource.Policy{Mode: resource.ModeObserve, MaxRSSBytes: 100}, nil)
	a.SetResourceControl(control)
	a.SetResourcePolicyUpdater(func(config.ResourceControlConfig) error { return fmt.Errorf("disk full") })
	response := httptest.NewRecorder()
	body := strings.NewReader(`{"mode":"terminate","max_rss_mb":2048,"sustain_seconds":30,"cooldown_seconds":300}`)
	a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/resources/policy", body))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	if got := control.Snapshot().Control.Mode; got != resource.ModeObserve {
		t.Fatalf("active mode=%q want observe", got)
	}
}

func TestResourcePolicyEndpointAuditsRejectedUpdates(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid payload", body: `{ "unknown": true }`},
		{name: "trailing payload", body: `{ "mode": "observe" } {}`},
		{name: "validation failure", body: `{ "mode": "destroy" }`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := testStore(t)
			a := New("", st, nil, func() Status { return Status{Running: true} })
			a.SetResourcePolicyUpdater(func(config.ResourceControlConfig) error { return nil })
			response := httptest.NewRecorder()
			a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/resources/policy", strings.NewReader(tt.body)))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			audits := st.RecentAudit(5)
			if len(audits) != 1 || audits[0].Action != "resource-policy-update-rejected" {
				t.Fatalf("audit=%+v", audits)
			}
		})
	}
}

func TestResourcePolicyEndpointSerializesPersistAndApply(t *testing.T) {
	a := New("", testStore(t), nil, func() Status { return Status{Running: true} })
	var active, overlap atomic.Int32
	a.SetResourcePolicyUpdater(func(config.ResourceControlConfig) error {
		if active.Add(1) != 1 {
			overlap.Store(1)
		}
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
		return nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := strings.NewReader(`{"mode":"observe","max_rss_mb":1024,"sustain_seconds":30,"cooldown_seconds":300}`)
			response := httptest.NewRecorder()
			a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/resources/policy", body))
			if response.Code != http.StatusOK {
				t.Errorf("code=%d body=%s", response.Code, response.Body.String())
			}
		}()
	}
	wg.Wait()
	if overlap.Load() != 0 {
		t.Fatal("resource policy updates overlapped persistence and application")
	}
}

func TestResourceControlResolveEndpoint(t *testing.T) {
	st := testStore(t)
	a := New("", st, nil, func() Status { return Status{Running: true} })
	control := resource.NewController(resource.Policy{
		Mode: resource.ModePrompt, MaxRSSBytes: 100,
	}, nil)
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	control.Observe(resource.Snapshot{Sessions: []resource.Session{{
		Key: "s1", RootPID: 10, RootStartedAt: now, Name: "claude", RSSBytes: 200,
	}}}, now)
	pending := control.Snapshot().Control.Pending
	if len(pending) != 1 {
		t.Fatalf("pending=%v", pending)
	}
	a.SetResourceControl(control)

	response := httptest.NewRecorder()
	body := strings.NewReader(`{"id":"` + pending[0].ID + `","decision":"dismiss"}`)
	a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/resources/control", body))
	if response.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	if len(control.Snapshot().Control.Pending) != 0 {
		t.Fatal("resolved action remained pending")
	}
	audits := st.RecentAudit(5)
	if len(audits) != 1 || audits[0].Action != "resource-control" || audits[0].ToMode != "dismiss" {
		t.Fatalf("audit=%+v", audits)
	}
}

func TestResourceControlResumeEndpoint(t *testing.T) {
	st := testStore(t)
	a := New("", st, nil, func() Status { return Status{Running: true} })
	var actions []resource.ControlAction
	control := resource.NewController(resource.Policy{Mode: resource.ModeTerminate, MaxRSSBytes: 100,
		Interventions: []resource.InterventionStep{{Action: resource.ActionPause}}},
		func(action resource.ControlAction) error { actions = append(actions, action); return nil })
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	control.Observe(resource.Snapshot{Sessions: []resource.Session{{
		Key: "s1", RootPID: 10, RootStartedAt: now, Name: "claude", RSSBytes: 200,
		Processes: []resource.Process{{PID: 10, StartedAt: now}},
	}}}, now)
	a.SetResourceControl(control)

	response := httptest.NewRecorder()
	body := strings.NewReader(`{"session_key":"s1","decision":"resume"}`)
	a.buildMux().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/resources/control", body))
	if response.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	if len(actions) != 2 || actions[1].Kind != "resume" {
		t.Fatalf("actions=%+v", actions)
	}
}
