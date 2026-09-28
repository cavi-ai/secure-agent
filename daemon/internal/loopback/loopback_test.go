package loopback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:11434", "http://127.0.0.1:11434", "https://[::1]:11434"} {
		if !ValidEndpoint(endpoint) {
			t.Errorf("rejected loopback endpoint %q", endpoint)
		}
	}
	for _, endpoint := range []string{
		"http://example.com", "ftp://localhost", "http://user@localhost",
		"http://localhost?next=example.com", "http://localhost#fragment", "localhost:11434",
	} {
		if ValidEndpoint(endpoint) {
			t.Errorf("accepted invalid model endpoint %q", endpoint)
		}
	}
}

func TestClientDoesNotReplayPromptOnRedirect(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, source.URL, strings.NewReader("private prompt"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Client(time.Second).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || forwarded.Load() != 0 {
		t.Fatalf("redirect status %d, forwarded %d times", resp.StatusCode, forwarded.Load())
	}
}
