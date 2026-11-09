package advisor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExternalAdvisorAuthenticatesAndFailsBeforeSendingOnKeyError(t *testing.T) {
	key := strings.Repeat("a", 43)
	path := filepath.Join(t.TempDir(), "model.key")
	if err := os.WriteFile(path, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"authorized"}}]}`)
	}))
	defer server.Close()
	s := New(Config{Enabled: true, Endpoint: server.URL, APIKeyFile: path}, &memSink{})
	answer, err := s.complete(context.Background(), s.client, "system", "user", 16)
	if err != nil || answer != "authorized" || requests.Load() != 1 {
		t.Fatalf("authenticated advisor: %q %v requests=%d", answer, err, requests.Load())
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	_, err = s.complete(context.Background(), s.client, "system", "private prompt", 16)
	if err == nil || requests.Load() != 1 || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), key) {
		t.Fatalf("key failure sent request or exposed credentials: %v count=%d", err, requests.Load())
	}
}

func TestClassifierUsesItsSeparateKeyForMetadataAndRouting(t *testing.T) {
	key := strings.Repeat("b", 43)
	path := filepath.Join(t.TempDir(), "classifier.key")
	if err := os.WriteFile(path, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/models" {
			fmt.Fprint(w, `{"data":[{"id":"kev-latest"}]}`)
		} else {
			fmt.Fprint(w, `{"answers":{"context":{"type":"choice","choice":"session","confidence":0.73,"probabilities":{"session":0.8,"operator_history":0.1,"sufficient":0.05,"unknown":0.05}}}}`)
		}
	}))
	defer server.Close()
	s := New(Config{Enabled: true, Endpoint: server.URL, APIKeyFile: "/missing/advisor.key", ClassifierEndpoint: server.URL, ClassifierAPIKeyFile: path}, &memSink{})
	s.ClassifierStatus(context.Background())
	answer, err := s.classifyEvidence(context.Background(), "recorded finding")
	if err != nil || !strings.Contains(answer, `"choice":"session"`) || requests.Load() != 2 {
		t.Fatalf("separate classifier credential: %s %v requests=%d", answer, err, requests.Load())
	}
}
