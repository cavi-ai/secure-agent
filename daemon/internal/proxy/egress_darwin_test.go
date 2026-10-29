package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/connpeer"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/taint"
)

// A routed curl in a session the hook marked tainted is refused before its
// request leaves when untrusted-egress is deny, and passes in monitor. The
// client process is found with netstat, as in the daemon.
func TestTaintedSessionEgressRefusedInDenyMode(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not installed")
	}
	var upstream atomic.Int32
	count := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		_, _ = w.Write([]byte("upstream"))
	})
	tlsBackend := httptest.NewTLSServer(count)
	defer tlsBackend.Close()
	plainBackend := httptest.NewServer(count)
	defer plainBackend.Close()

	dir := t.TempDir()
	taintDir := filepath.Join(dir, "taint")
	if err := os.MkdirAll(taintDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("sess-1"))
	record := filepath.Join(taintDir, hex.EncodeToString(sum[:])[:32]+".json")
	if err := os.WriteFile(record, []byte(`{"source":"web: https://evil.example/page"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	modes := filepath.Join(dir, "guard-modes.json")
	var attributed atomic.Int32
	gate := &taint.Gate{
		Dir:              taintDir,
		ModesPath:        modes,
		CwdOverridesPath: filepath.Join(dir, "guard-cwd-overrides.json"),
		ClientPID: func(ctx context.Context, addr string) (int32, error) {
			return connpeer.PID(ctx, addr, api.TCPClientPID)
		},
		Session: func(pid int32) (string, string, bool) {
			attributed.Store(pid)
			return "sess-1", "/work/app", true
		},
	}

	ps, tok, _ := startRouteProxy(t)
	ps.SetEgressGate(gate.Check)
	sub := ps.bus.Subscribe()

	// run fetches target through the proxy and returns curl's pid and the
	// status of the CONNECT (https) or the request (http).
	run := func(target string) (int32, string) {
		t.Helper()
		format := "%{http_code}"
		if strings.HasPrefix(target, "https:") {
			format = "%{http_connect}"
		}
		cmd := exec.Command(curl, "-sk", "-o", "/dev/null", "-w", format, "--max-time", "10",
			"--proxy", fmt.Sprintf("http://tunnel:%s@127.0.0.1:%d", tok, ps.Port()), target)
		var out strings.Builder
		cmd.Stdout = &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := int32(cmd.Process.Pid)
		_ = cmd.Wait()
		return pid, out.String()
	}

	if err := os.WriteFile(modes, []byte(`{"untrusted-egress":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{tlsBackend.URL, plainBackend.URL} {
		pid, status := run(target)
		if status != "403" {
			t.Fatalf("%s in deny mode: status %q, want 403", target, status)
		}
		if got := attributed.Load(); got != pid {
			t.Fatalf("%s: attributed pid %d, curl was %d", target, got, pid)
		}
		select {
		case ev := <-sub:
			if ev.Kind != event.KindProxyHit || ev.PID != pid || ev.SessionID != "sess-1" ||
				!strings.HasPrefix(ev.Detail, "proxy-untrusted-egress: 127.0.0.1 after untrusted content (web: https://evil.example/page)") {
				t.Fatalf("%s: event %+v", target, ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no refusal published", target)
		}
	}
	if n := upstream.Load(); n != 0 {
		t.Fatalf("upstream saw %d requests in deny mode", n)
	}

	if err := os.WriteFile(modes, []byte(`{"untrusted-egress":"monitor"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{tlsBackend.URL, plainBackend.URL} {
		if _, status := run(target); status != "200" {
			t.Fatalf("%s in monitor mode: status %q, want 200", target, status)
		}
	}
	if n := upstream.Load(); n != 2 {
		t.Fatalf("upstream saw %d requests in monitor mode, want 2", n)
	}
}
