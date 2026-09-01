package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type fakeKiller struct {
	killed int32
}

func (f *fakeKiller) Kill(pid int32) error {
	f.killed = pid
	return nil
}

func testStore(t *testing.T) *store.Store {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "test.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func unixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 2 * time.Second,
	}
}

func waitForSocket(t *testing.T, socketPath string) {
	for i := 0; i < 20; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socket %s not ready", socketPath)
}

func TestKillEndpointInvokesKiller(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	fk := &fakeKiller{}
	a := New(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":7}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("kill post: %v status=%v", err, resp.StatusCode)
	}
	if fk.killed != 7 {
		t.Fatalf("killer got pid %d, want 7", fk.killed)
	}
}

func TestFirewallModeEndpointPromotesAndPersists(t *testing.T) {
	dir := t.TempDir()
	// Short socket path: a unix socket path must fit in sockaddr_un (~104 chars),
	// and t.TempDir() with this long test name overflows it.
	sock := fmt.Sprintf("/tmp/sa_test_fwmode_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	eng, err := firewall.NewEngine(config.FirewallConfig{
		Mode:     "monitor",
		Patterns: []config.PatternConfig{{ID: "aws-key", Type: "cloud-key", Re: `AKIA[0-9A-Z]{16}`, Mode: "monitor"}},
	}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	modes := firewall.NewModeStore(filepath.Join(dir, "firewall-modes.json"))

	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetFirewall(FirewallControl{Engine: eng, Modes: modes})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/firewall/mode", "application/json", strings.NewReader(`{"rule":"aws-key","mode":"block"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("firewall mode post: %v status=%v", err, resp.StatusCode)
	}
	if eng.RuleMode("aws-key") != firewall.ModeBlock {
		t.Fatal("rule was not promoted to block in the engine")
	}
	if modes.Load()["aws-key"] != "block" {
		t.Fatal("promotion was not persisted to the mode store")
	}
}

func TestFlagsAndEventsEndpointsApplyFilters(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	st.PutFlag(model.Flag{ID: "a", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude", PID: 1, TS: now})
	st.PutFlag(model.Flag{ID: "b", Rule: "keychain-access", Severity: 1, Agent: "cursor", PID: 2, TS: now})
	st.PutEvent(event.Event{Kind: event.KindProxyHit, PID: 20, TS: now})
	st.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 30, TS: now})

	sock := fmt.Sprintf("/tmp/sa_test_filt_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	get := func(path string) string {
		resp, err := cl.Get("http://unix" + path)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("GET %s: %v status=%v", path, err, resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// flags: agent filter returns only that agent's flag
	if body := get("/flags?agent=cursor"); !strings.Contains(body, `"id":"b"`) || strings.Contains(body, `"id":"a"`) {
		t.Fatalf("flags?agent=cursor = %s", body)
	}
	// flags: min_severity keeps sev>=3 only
	if body := get("/flags?min_severity=3"); !strings.Contains(body, `"id":"a"`) || strings.Contains(body, `"id":"b"`) {
		t.Fatalf("flags?min_severity=3 = %s", body)
	}
	// events: kind=9 (ProxyHit) keeps only the proxy event (pid 20)
	proxyKind := int(event.KindProxyHit)
	if body := get(fmt.Sprintf("/events?kind=%d", proxyKind)); !strings.Contains(body, `"pid":20`) || strings.Contains(body, `"pid":30`) {
		t.Fatalf("events?kind=ProxyHit = %s", body)
	}
}

func TestFirewallModePromotionIsAudited(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sa_test_audit_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	eng, err := firewall.NewEngine(config.FirewallConfig{
		Mode:     "monitor",
		Patterns: []config.PatternConfig{{ID: "aws-key", Type: "cloud-key", Re: `AKIA[0-9A-Z]{16}`, Mode: "monitor"}},
	}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	modes := firewall.NewModeStore(filepath.Join(dir, "firewall-modes.json"))

	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetFirewall(FirewallControl{Engine: eng, Modes: modes})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/firewall/mode", "application/json", strings.NewReader(`{"rule":"aws-key","mode":"block"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("firewall mode post: %v status=%v", err, resp.StatusCode)
	}

	auditResp, err := cl.Get("http://unix/audit")
	if err != nil || auditResp.StatusCode != 200 {
		t.Fatalf("audit get: %v status=%v", err, auditResp.StatusCode)
	}
	body, _ := io.ReadAll(auditResp.Body)
	for _, want := range []string{`"action":"rule-mode"`, `"rule":"aws-key"`, `"from_mode":"monitor"`, `"to_mode":"block"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("audit response missing %s: %s", want, body)
		}
	}
}

func TestFingerprintIngestEndpointReturnsLabels(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_test_fping_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	called := false
	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetFirewall(FirewallControl{
		Ingest: func() ([]string, error) {
			called = true
			return []string{"STRIPE (~/.env)"}, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/firewall/fingerprints/ingest", "application/json", nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingest post: %v status=%v", err, resp.StatusCode)
	}
	if !called {
		t.Fatal("ingest callback was not invoked")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "STRIPE") {
		t.Fatalf("response missing registered label: %s", body)
	}
}

func TestFirewallSourcesAddRemoveAndAudit(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sa_test_src_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	srcStore := firewall.NewSourceStore(filepath.Join(dir, "firewall-sources.json"))
	ingestCalls := 0

	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetFirewall(FirewallControl{
		Sources:     srcStore,
		BaseSources: []string{"/etc/agent/defaults.env"},
		Ingest: func() ([]string, error) {
			ingestCalls++
			return []string{"KEY (src)"}, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	// A real, user-owned regular file passes validation.
	srcFile := filepath.Join(dir, "app.env")
	if err := os.WriteFile(srcFile, []byte("API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A system path is refused: the daemon reads sources as root, so source-add
	// must not become an arbitrary-file-read.
	sysResp, _ := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(`{"source":"/etc/master.passwd","op":"add"}`))
	if sysResp.StatusCode != 400 {
		t.Fatalf("add of system path status=%d, want 400", sysResp.StatusCode)
	}

	// add the real source
	resp, err := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(fmt.Sprintf(`{"source":%q,"op":"add"}`, srcFile)))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("add post: %v status=%v", err, resp.StatusCode)
	}
	if ingestCalls != 1 {
		t.Fatalf("add should re-ingest once, got %d calls", ingestCalls)
	}

	// GET shows config (read-only) + the user source
	getResp, _ := cl.Get("http://unix/firewall/sources")
	body, _ := io.ReadAll(getResp.Body)
	if !strings.Contains(string(body), `"source":"/etc/agent/defaults.env","origin":"config"`) {
		t.Fatalf("sources GET missing config source: %s", body)
	}
	if !strings.Contains(string(body), srcFile) || !strings.Contains(string(body), `"origin":"user"`) {
		t.Fatalf("sources GET missing user source %s: %s", srcFile, body)
	}

	// audit row carries the path
	auditResp, _ := cl.Get("http://unix/audit")
	auditBody, _ := io.ReadAll(auditResp.Body)
	if !strings.Contains(string(auditBody), `"action":"source-add"`) || !strings.Contains(string(auditBody), srcFile) {
		t.Fatalf("audit missing source-add row with path: %s", auditBody)
	}

	// removing a config source is rejected
	badResp, _ := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(`{"source":"/etc/agent/defaults.env","op":"remove"}`))
	if badResp.StatusCode != 400 {
		t.Fatalf("remove of config source status=%d, want 400", badResp.StatusCode)
	}

	// removing the user source succeeds and re-ingests again
	rmResp, _ := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(fmt.Sprintf(`{"source":%q,"op":"remove"}`, srcFile)))
	if rmResp.StatusCode != 200 {
		t.Fatalf("remove user source status=%d, want 200", rmResp.StatusCode)
	}
	if ingestCalls != 2 {
		t.Fatalf("remove should re-ingest, total calls = %d, want 2", ingestCalls)
	}
	if len(srcStore.Load()) != 0 {
		t.Fatalf("user source not removed: %v", srcStore.Load())
	}
}
