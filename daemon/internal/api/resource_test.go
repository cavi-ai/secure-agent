package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

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
		RSSBytes:   300, CPUPercent: 75, ProcessCount: 2, SessionCount: 1,
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
	var got resource.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}
