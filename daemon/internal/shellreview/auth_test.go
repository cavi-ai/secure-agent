package shellreview

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

func TestShellClassifierKeyFailureCannotSendEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shell.key")
	key := strings.Repeat("c", 43)
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
		fmt.Fprint(w, reviewReply)
	}))
	defer server.Close()
	s := &Service{cfg: Config{Endpoint: server.URL, APIKeyFile: path, TimeoutMS: 1000}}
	answer, reason := s.classify(context.Background(), "echo fixture", "/workspace")
	if reason != "" || answer.Choice != "review" || requests.Load() != 1 {
		t.Fatalf("authenticated classification: %+v %s requests=%d", answer, reason, requests.Load())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, reason = s.classify(context.Background(), "private command", "/workspace")
	if reason != "model_unavailable" || requests.Load() != 1 {
		t.Fatal("classifier sent command after key file became unavailable")
	}
}
