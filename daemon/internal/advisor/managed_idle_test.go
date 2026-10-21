package advisor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func init() {
	if os.Getenv("SECURE_AGENT_TEST_MODEL_PROCESS") != "1" {
		return
	}
	port := ""
	for i, v := range os.Args {
		if v == "--port" && i+1 < len(os.Args) {
			port = os.Args[i+1]
		}
	}
	http.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"data":[{"id":"fixture"}]}`) })
	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"content":"fixture"}}]}`)
	})
	_ = http.ListenAndServe("127.0.0.1:"+port, nil)
	os.Exit(0)
}

func TestManagedModelStartsOnDemandAndReapsOnIdle(t *testing.T) {
	t.Setenv("SECURE_AGENT_TEST_MODEL_PROCESS", "1")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManagedTransport(ManagedSpec{Model: "fixture", Bin: bin})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.idle = 20 * time.Millisecond
	if m.loaded() {
		t.Fatal("managed model started without a request")
	}
	call := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1/v1/chat/completions", strings.NewReader(`{}`))
		resp, err := m.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	call()
	deadline := time.Now().Add(time.Second)
	for m.loaded() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.loaded() {
		t.Fatal("idle model process survived its expiry")
	}
	call()
	if !m.loaded() {
		t.Fatal("expired model could not restart on demand")
	}
	m.Close()
	if m.loaded() {
		t.Fatal(fmt.Errorf("closed managed model retained its process"))
	}
}
