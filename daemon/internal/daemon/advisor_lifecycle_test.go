package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func TestAdvisorReloadStartsAndReplacesWorker(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	hits := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		hits <- request.Model
		w.WriteHeader(503)
	}))
	defer srv.Close()
	path := filepath.Join(home, "config.yaml")
	write := func(model string) {
		if err := os.WriteFile(path, []byte("advisor:\n  enabled: true\n  endpoint: "+srv.URL+"\n  model: "+model+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(filepath.Join(home, "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Agents = nil
	cfg.Advisor.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := &advisorStackHolder{}
	h.Store(setupAdvisor(cfg, st, nil, nil))
	go h.Run(ctx, supervise.New(supervise.NewRegistry()))
	defer h.Close()
	go watchConfig(ctx, path, configWatchDeps{st: st, stk: h, initialConfig: &cfg})
	// Persist a real flag: a new advisor generation must process its backfill.
	st.PutFlag(model.Flag{ID: "one", Rule: "proxy-secret-leak", Severity: 3, TS: time.Now()})
	write("first")
	select {
	case got := <-hits:
		if got != "first" {
			t.Fatalf("model=%q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enabled advisor has no worker")
	}
	write("second")
	select {
	case got := <-hits:
		if got != "second" {
			t.Fatalf("reload used model=%q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replacement advisor has no worker")
	}
}

func TestAdvisorOwnerReapsManagedProcessOnReplaceAndClose(t *testing.T) {
	start := func() *exec.Cmd {
		cmd := exec.Command("sleep", "60")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		return cmd
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &advisorStackHolder{}
	first := start()
	h.Store(advisorStack{Managed: first})
	go h.Run(ctx, supervise.New(supervise.NewRegistry()))
	second := start()
	h.Store(advisorStack{Managed: second})
	if first.ProcessState == nil {
		t.Fatal("replaced process was not reaped")
	}
	h.Close()
	if second.ProcessState == nil {
		t.Fatal("current process was not reaped")
	}
	// A config reload already constructing a process when shutdown begins
	// must dispose of that late generation too.
	late := start()
	h.Store(advisorStack{Managed: late})
	if late.ProcessState == nil {
		t.Fatal("late reload orphaned its process")
	}
}
