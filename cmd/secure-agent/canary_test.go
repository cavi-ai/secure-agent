package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

type daemonCall struct{ method, path, body string }

// canaryDaemon serves the firewall source and ingest routes on a unix socket
// and records each request; sourceStatus is the answer to the source add.
func canaryDaemon(t *testing.T, sourceStatus int) (*http.Client, func() []daemonCall) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sa-canary")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []daemonCall
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, daemonCall{r.Method, r.URL.Path, string(b)})
		mu.Unlock()
		switch r.URL.Path {
		case "/firewall/sources":
			w.WriteHeader(sourceStatus)
			w.Write([]byte(`{"status":"ok"}`))
		case "/firewall/fingerprints/ingest":
			w.Write([]byte(`{"registered":["AWS_SECRET_ACCESS_KEY (canary.env)","GITHUB_TOKEN (canary.env)"]}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return unixClient(sock), func() []daemonCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]daemonCall(nil), calls...)
	}
}

func TestCanaryPlantWritesDecoysAndRegistersThem(t *testing.T) {
	client, calls := canaryDaemon(t, http.StatusOK)
	path := filepath.Join(t.TempDir(), "canary.env")
	var out bytes.Buffer
	if code := canaryPlant(&out, path, rand.Reader, client); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("planted file: %v mode %v", err, info.Mode())
	}
	data, _ := os.ReadFile(path)
	for _, shape := range []string{
		`(?m)^AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}$`,
		`(?m)^AWS_SECRET_ACCESS_KEY=[A-Za-z0-9/+]{40}$`,
		`(?m)^GITHUB_TOKEN=ghp_[A-Za-z0-9]{36}$`,
		`(?m)^OPENAI_API_KEY=sk-proj-[A-Za-z0-9_-]{48}$`,
		`(?m)^ANTHROPIC_API_KEY=sk-ant-api03-[A-Za-z0-9_-]{95}$`,
		`(?m)^STRIPE_SECRET_KEY=sk_live_[A-Za-z0-9]{24}$`,
	} {
		if !regexp.MustCompile(shape).Match(data) {
			t.Errorf("no line matches %s in:\n%s", shape, data)
		}
	}
	var add map[string]string
	got := calls()
	if len(got) != 2 || got[0].method != http.MethodPost || got[0].path != "/firewall/sources" ||
		json.Unmarshal([]byte(got[0].body), &add) != nil || add["source"] != path || add["op"] != "add" ||
		got[1].method != http.MethodPost || got[1].path != "/firewall/fingerprints/ingest" {
		t.Fatalf("daemon calls = %+v", got)
	}
	if !strings.Contains(out.String(), "GITHUB_TOKEN (canary.env)") {
		t.Fatalf("output does not list the registered labels: %s", out.String())
	}

	again, before := path, string(data)
	if code := canaryPlant(&out, again, rand.Reader, client); code != 1 {
		t.Fatal("planting over an existing file succeeded")
	}
	if now, _ := os.ReadFile(path); string(now) != before || len(calls()) != 2 {
		t.Fatal("a refused plant changed the file or called the daemon")
	}
}

func TestCanaryPlantRemovesTheFileWhenRegistrationFails(t *testing.T) {
	client, calls := canaryDaemon(t, http.StatusBadRequest)
	path := filepath.Join(t.TempDir(), "canary.env")
	var out bytes.Buffer
	if code := canaryPlant(&out, path, rand.Reader, client); code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, out.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("decoy left behind after the daemon refused the source: %v", err)
	}
	if got := calls(); len(got) != 1 {
		t.Fatalf("ingest ran after the source was refused: %+v", got)
	}
}
