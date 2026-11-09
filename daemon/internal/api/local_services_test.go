package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func TestLocalServicesUsesExplicitEndpointsWithoutChangingConfiguration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer srv.Close()
	a := newTestAPI(Deps{Store: testStore(t)})
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/local-services?endpoint="+url.QueryEscape(srv.URL), nil))
	var report localservice.Report
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &report) != nil || len(report.Services) != 1 || report.Services[0].Metadata.State != "access_refused" {
		t.Fatalf("endpoint disappeared: %d %s", w.Code, w.Body.String())
	}
	if !apiroutes.IsNoAgent("/local-services") || !apiroutes.ConsoleAllowed("GET", "/local-services") {
		t.Fatal("console assessment must require the existing NoAgent peer gate")
	}
	for _, target := range []string{"/local-services?endpoint=http://example.com", "/local-services?unexpected=true"} {
		w = httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 400 {
			t.Fatalf("unsafe/unknown query accepted: %d %s", w.Code, w.Body.String())
		}
	}
	w = httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("POST", "/local-services", nil))
	if w.Code != 405 {
		t.Fatalf("mutation accepted: %d", w.Code)
	}
}

func TestLocalServicesIncludesConfiguredAndRunningManagedEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "advisor:\n  enabled: true\n  endpoint: " + srv.URL + "\nsystem_agent:\n  enabled: true\n  endpoint: " + srv.URL + "\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI(Deps{Store: testStore(t), ConfigPath: path, Advisors: AdvisorDeps{ManagedModel: func() *localservice.ManagedRuntime {
		return &localservice.ManagedRuntime{State: "unloaded", Transport: "inherited-unix-v1", Enforcement: "private_transport"}
	}}})
	targets, err := a.localServiceTargets(nil)
	if err != nil || strings.Count(strings.Join(targets, ","), srv.URL) != 2 {
		t.Fatalf("configured endpoint selection: %v, %v", targets, err)
	}
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/local-services?endpoint="+url.QueryEscape(srv.URL), nil))
	var report localservice.Report
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &report) != nil || report.Managed == nil || report.Managed.Transport != "inherited-unix-v1" || report.Managed.State != "unloaded" {
		t.Fatalf("private managed transport missing: %d %s", w.Code, w.Body.String())
	}
	if err := os.WriteFile(path, []byte("advisor: ["), 0600); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/local-services", nil))
	if w.Code != 503 {
		t.Fatalf("configuration failure hidden behind default targets: %d %s", w.Code, w.Body.String())
	}
	unchanged, _ := os.ReadFile(path)
	if string(unchanged) != "advisor: [" {
		t.Fatal("assessment changed server configuration")
	}
}
