package advisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClassifierUsesTypedRoutingAndMasksState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/systemone" {
			t.Error(r.URL.Path)
		}
		var req struct {
			State, Model string
			Questions    map[string]struct {
				Type     string
				Criteria map[string]string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if strings.Contains(req.State, "secret-fixture") || !strings.Contains(req.State, "[REDACTED]") || req.Model != "local-kev" || req.Questions["context"].Type != "choice" || len(req.Questions["context"].Criteria) != 4 {
			t.Errorf("invalid classifier request: %+v", req)
		}
		w.Write([]byte(`{"answers":{"context":{"type":"choice","choice":"session","confidence":0.8,"probabilities":{"session":0.8,"operator_history":0.1,"sufficient":0.05,"unknown":0.05}}}}`))
	}))
	defer srv.Close()
	s := New(Config{Enabled: true, Endpoint: srv.URL, ClassifierEndpoint: srv.URL, ClassifierModel: "local-kev", Mask: func(v string) (string, bool) { return strings.ReplaceAll(v, "secret-fixture", "[REDACTED]"), true }}, &memSink{})
	result, err := s.classifyEvidence(context.Background(), "secret-fixture")
	if err != nil || !strings.Contains(result, `"advisory_only":true`) || !strings.Contains(result, `"choice":"session"`) {
		t.Fatalf("result=%s err=%v", result, err)
	}
}

func TestClassifierUnavailableAndInvalidOutputsCannotBecomeAdvice(t *testing.T) {
	for _, response := range []string{`not json`, `{"answers":{"context":{"type":"choice","choice":"allow-secret","probabilities":{}}}}`, `{"answers":{"context":{"type":"choice","choice":"session","probabilities":{"session":0.8,"operator_history":0.8,"sufficient":0.8,"unknown":0.8}}}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(response)) }))
		s := New(Config{Enabled: true, Endpoint: srv.URL, ClassifierEndpoint: srv.URL}, &memSink{})
		result, err := s.classifyEvidence(context.Background(), "a fixture finding")
		srv.Close()
		if err != nil || !strings.Contains(result, `"available":false`) || s.Health().CircuitOpen {
			t.Fatalf("malformed classifier output affected advisor: %s %v", result, err)
		}
	}
	s := New(Config{Enabled: true, Endpoint: "http://127.0.0.1:1", ClassifierEndpoint: "http://127.0.0.1:1"}, &memSink{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	result, err := s.classifyEvidence(ctx, "a fixture finding")
	if err != nil || !strings.Contains(result, `"available":false`) {
		t.Fatalf("offline classifier did not fall back: %s %v", result, err)
	}
	if New(Config{Enabled: true, Endpoint: "http://127.0.0.1:1", ClassifierEndpoint: "https://example.com"}, &memSink{}) != nil {
		t.Fatal("remote classifier accepted")
	}
}
