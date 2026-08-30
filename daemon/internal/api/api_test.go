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

func TestRotateEndpointExecutesRotation(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")
	_ = os.WriteFile(envPath, []byte("MY_API_KEY=secret_val_123\n"), 0600)

	st := testStore(t)
	st.PutIncident(model.IncidentReport{
		ID:        "inc-test-1",
		FlagID:    "flag-1",
		PID:       99,
		Agent:     "cursor",
		Timestamp: time.Now(),
		Rule:      "sensitive-read-then-connect",
		Summary:   "Test incident summary",
		Risk:      model.RiskCritical,
		RotateList: []model.RotateItem{
			{
				ID:       "rot-item-1",
				Category: model.CategoryEnvSecrets,
				Name:     ".env",
				Path:     envPath,
				Risk:     model.RiskCritical,
			},
		},
	})

	sock := fmt.Sprintf("/tmp/sa_test_rot_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	fk := &fakeKiller{}
	a := New(sock, st, fk, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/rotate", "application/json", strings.NewReader(`{"incident_id":"inc-test-1","item_id":"rot-item-1"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("rotate post: %v status=%v", err, resp.StatusCode)
	}

	newBytes, _ := os.ReadFile(envPath)
	if strings.Contains(string(newBytes), "secret_val_123") {
		t.Fatal("secret value was not rotated via /rotate API endpoint!")
	}
}
