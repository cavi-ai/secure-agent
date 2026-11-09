package localservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAssessmentReportsMetadataExposureWithoutClaimingProtection(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v1/models" || r.Body != http.NoBody || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("assessment made a non-metadata request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte(`{"data":[{"id":"private-model-name"}]}`))
	}))
	defer srv.Close()
	report, err := Assess(context.Background(), []string{srv.URL, srv.URL + "/"})
	if err != nil || len(report.Services) != 1 {
		t.Fatalf("deduplicated report: %+v, %v", report, err)
	}
	s := report.Services[0]
	if s.Metadata.State != "model_metadata" || s.CrossOrigin.Sharing != "advertised" || s.ForeignHost.State != "model_metadata" {
		t.Fatalf("missing observed exposure: %+v", s)
	}
	if report.Enforcement != "not_assessed" || s.Enforcement != "not_assessed" || len(s.Findings) != 3 || calls.Load() != 3 {
		t.Fatalf("incorrect coverage or request budget: %+v; calls=%d", report, calls.Load())
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "private-model-name") {
		t.Fatal("metadata body retained in assessment")
	}
}

func TestRefusedEndpointRemainsVisibleAndUnidentified(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	report, err := Assess(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	s := report.Services[0]
	if s.Metadata.State != "access_refused" || s.Metadata.Status != 401 || s.CrossOrigin.State != "not_checked" || s.Enforcement != "not_assessed" || calls.Load() != 1 {
		t.Fatalf("authentication response mistaken for absence or protection: %+v", s)
	}
}

func TestAssessmentRejectsRemoteTargetsAndCredentialsBeforeAnyRequest(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "http://127.0.0.1.example.com", "http://0.0.0.0:8080", "http://192.168.1.2", "ftp://127.0.0.1", "http://user:secret@127.0.0.1", "http://127.0.0.1?token=secret", "http://127.0.0.1#secret", "http://127.0.0.1:0", "http://127.0.0.1:65536", ""} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := Assess(context.Background(), []string{endpoint}); err == nil {
				t.Fatal("unsafe endpoint accepted")
			}
		})
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	if _, err := Assess(context.Background(), []string{srv.URL, "http://example.com"}); err == nil || calls.Load() != 0 {
		t.Fatal("validation must precede every network request")
	}
	if _, err := Assess(context.Background(), make([]string, 17)); err == nil {
		t.Fatal("endpoint limit not enforced")
	}
}

func TestAssessmentNeverFollowsRedirectsOrEnvironmentProxies(t *testing.T) {
	var redirected, proxied atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	report, err := Assess(context.Background(), []string{srv.URL})
	if err != nil || report.Services[0].Metadata.State != "redirect_refused" || redirected.Load() != 0 || proxied.Load() != 0 {
		t.Fatalf("redirect or proxy boundary failed: %+v, %v", report, err)
	}
}

func TestMetadataBodyAndDeadlineAreBounded(t *testing.T) {
	for _, tc := range []struct{ name, body, state string }{
		{"oversized", strings.Repeat("x", 65537), "response_too_large"},
		{"malformed", `{"data":`, "non_model_response"},
		{"unrelated", `{"data":null}`, "non_model_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) }))
			defer srv.Close()
			report, err := Assess(context.Background(), []string{srv.URL})
			if err != nil || report.Services[0].Metadata.State != tc.state {
				t.Fatalf("body boundary: %+v, %v", report, err)
			}
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	report, err := Assess(ctx, []string{srv.URL})
	if err != nil || report.Services[0].Metadata.State != "unavailable" || time.Since(start) > time.Second {
		t.Fatalf("deadline or unknown state lost: %+v, %v", report, err)
	}
}

func TestOriginAndHostRejectionAreSeparateObservations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || strings.Contains(r.Host, ".invalid") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	report, err := Assess(context.Background(), []string{srv.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	s := report.Services[0]
	if s.Metadata.State != "model_metadata" || s.CrossOrigin.State != "access_refused" || s.ForeignHost.State != "access_refused" || len(s.Findings) != 1 || s.Enforcement != "not_assessed" {
		t.Fatalf("metadata checks became an enforcement verdict: %+v", s)
	}
}

func TestAssessmentPinsLocalhostAndIPv6ToLoopback(t *testing.T) {
	serve := func(t *testing.T, listener net.Listener, endpoint string) {
		t.Helper()
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"data":[]}`))
		}))
		srv.Listener = listener
		srv.Start()
		defer srv.Close()
		report, err := Assess(context.Background(), []string{endpoint})
		if err != nil || report.Services[0].Metadata.State != "model_metadata" {
			t.Fatalf("loopback family unavailable: %+v, %v", report, err)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(t, listener, fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port))
	listener, err = net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(t, listener, "http://"+listener.Addr().String())
	if conn, err := dialLoopback(context.Background(), "tcp", "example.com:80"); err == nil {
		conn.Close()
		t.Fatal("dialer resolved a non-loopback hostname")
	}
}

func TestAssessmentBoundsConcurrentServicesAndRejectsAmbiguousCORS(t *testing.T) {
	var active, peak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Origin", "https://secure-agent-probe.invalid")
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	endpoints := make([]string, 16)
	for i := range endpoints {
		endpoints[i] = fmt.Sprintf("%s/service-%d", server.URL, i)
	}
	report, err := Assess(context.Background(), endpoints)
	if err != nil || len(report.Services) != 16 || peak.Load() > 4 {
		t.Fatalf("concurrency budget exceeded: peak=%d, %v", peak.Load(), err)
	}
	for _, service := range report.Services {
		if service.Metadata.State != "model_metadata" || service.CrossOrigin.Sharing != "not_advertised" || len(service.Findings) != 2 {
			t.Fatalf("ambiguous CORS headers treated as browser access: %+v", service)
		}
	}
}
