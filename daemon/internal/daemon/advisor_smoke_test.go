package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAdvisorSmokeVerdict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("HERMES_HOME", home)
	t.Setenv("OPENCLAW_HOME", home)
	t.Setenv("CODEX_HOME", home)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"assessment\":\"benign\",\"confidence\":0.9,\"rationale\":\"routine workflow\",\"suggested_action\":\"none\"}"}}]}`))
	}))
	defer srv.Close()
	cfg, err := config.Load(filepath.Join(home, "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Firewall.Registry.SaltRef = filepath.Join(home, "fw-salt")
	cfg.Advisor.Enabled = true
	cfg.Advisor.Endpoint = srv.URL
	cfg.Advisor.Model = "e2e-stub-4b"
	cfg.Advisor.Timeout = 4 * time.Second
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Agents = []config.AgentDef{{Name: "cursor", Match: []string{exe}}}
	cfg.SocketPath = filepath.Join(home, "daemon.sock")
	cfg.DBPath = filepath.Join(home, "events.db")
	cfg.JSONLPath = filepath.Join(home, "events.jsonl")
	cfg.OpenclawHome = home
	cfg.HermesHome = home
	cfg.ProxyEnabled = true
	cfg.ProxyPort = 0
	c, err := Build(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()
	h := c.advisor
	now := time.Now()
	pid := int32(os.Getpid())
	c.bus.Publish(event.Event{Kind: event.KindPluginAction, TS: now, PID: pid, Path: filepath.Join(home, ".env")})
	c.bus.Publish(event.Event{Kind: event.KindConnOpen, TS: now.Add(time.Millisecond), PID: pid, RemoteHost: "192.168.64.2", RemotePort: 49183})
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", cfg.SocketPath)
	}}}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://unix/flags")
		if err != nil {
			t.Fatal(err)
		}
		var flags []model.Flag
		err = json.NewDecoder(resp.Body).Decode(&flags)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, fl := range flags {
			if fl.PID == pid && fl.Rule == "sensitive-read-then-connect" && fl.Advisor != nil && fl.Advisor.Assessment == "benign" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("missing verdict: advisor health=%+v", h.Load().Sub.Health())
}
