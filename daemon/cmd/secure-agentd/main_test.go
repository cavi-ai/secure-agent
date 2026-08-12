package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

type fakeProcSource struct{}

func (f fakeProcSource) List() []agents.ProcInfo {
	return []agents.ProcInfo{
		{PID: 500, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"},
	}
}

func (f fakeProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 500 {
		return agents.ProcInfo{PID: 500, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"}, true
	}
	return agents.ProcInfo{}, false
}

func TestFullBusCorrelatorStorePipeline(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg, _ := config.Load("/nonexistent")
	b := bus.New(64)
	defer b.Close()

	tg := agents.New(cfg, fakeProcSource{})
	tg.Refresh()

	cl := sensitive.New(cfg)
	cr := correlate.New(tg, cl, cfg)

	sub := b.Subscribe()
	done := make(chan struct{})
	go func() {
		for e := range sub {
			st.PutEvent(e)
			flags := cr.Observe(e)
			for _, fl := range flags {
				st.PutFlag(fl)
			}
		}
		close(done)
	}()

	now := time.Now()
	// 1. Publish sensitive file read
	b.Publish(event.Event{
		Kind: event.KindPluginAction,
		TS:   now,
		PID:  500,
		Path: "/Users/x/project/.env",
	})

	time.Sleep(50 * time.Millisecond)

	// 2. Publish foreign network egress
	b.Publish(event.Event{
		Kind:       event.KindConnOpen,
		TS:         now.Add(100 * time.Millisecond),
		PID:        500,
		RemoteHost: "evil.example.com",
		RemotePort: 443,
	})

	time.Sleep(100 * time.Millisecond)

	flags := st.RecentFlags(10)
	if len(flags) != 1 {
		t.Fatalf("expected 1 flag in store, got %d", len(flags))
	}
	if flags[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("rule = %s, want sensitive-read-then-connect", flags[0].Rule)
	}

	b.Close()
	<-done
}

func TestEndToEndSmokeScenario(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "d.sock")
	dbPath := filepath.Join(dir, "t.db")
	jsonlPath := filepath.Join(dir, "t.jsonl")
	actPath := filepath.Join(dir, "activity.jsonl")

	cfg := config.Config{
		Agents: []config.AgentDef{
			{Name: "cursor", Match: []string{"test-agent", "cursor", "secure-agentd.test"}},
		},
		VendorAllowlist: map[string][]string{
			"cursor": {"cursor.sh", "cursor.com"},
		},
		NetSampleInterval: 100 * time.Millisecond,
		SocketPath:        sockPath,
		DBPath:            dbPath,
		JSONLPath:         jsonlPath,
		KeychainMarkers:   []string{"keychain"},
	}

	st, err := store.Open(dbPath, jsonlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	b := bus.New(256)
	defer b.Close()

	tg := agents.New(cfg, agents.NewDarwinProcSource())
	tg.Refresh()

	cl := sensitive.New(cfg)
	cr := correlate.New(tg, cl, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := b.Subscribe()
	go func() {
		for e := range sub {
			st.PutEvent(e)
			for _, fl := range cr.Observe(e) {
				st.PutFlag(fl)
			}
		}
	}()

	statusFn := func() api.Status { return api.Status{Running: true} }
	apiServer := api.New(sockPath, st, &realKiller{}, statusFn)
	go apiServer.Serve(ctx)

	go supervise.Run(ctx, "netsample", func(c context.Context) error {
		ns := collect.NewNetSampler(b, tg, cfg.NetSampleInterval, nil)
		return ns.Run(c)
	})

	go supervise.Run(ctx, "transcript", func(c context.Context) error {
		ts := collect.NewTranscriptScanner(b, []string{actPath})
		return ts.Run(c)
	})

	time.Sleep(200 * time.Millisecond)

	// Simulate agent activity
	currPID := int32(os.Getpid()) // test process PID
	info, _ := agents.NewDarwinProcSource().Info(currPID)
	t.Logf("TEST RUNNER PID: %d, EXE: %q", currPID, info.Exe)
	// 1. Write sensitive read log
	envPath := filepath.Join(dir, ".env")
	os.WriteFile(envPath, []byte("SECRET=123\n"), 0644)

	rec := fmt.Sprintf(`{"tool":"Read","file_path":%q,"pid":%d}`, envPath, currPID)
	os.WriteFile(actPath, []byte(rec+"\n"), 0644)

	// 2. Open foreign TCP socket
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		connCh <- c
	}()

	cliConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	// Wait for flag via API
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
		Timeout: 2 * time.Second,
	}

	flagFound := false
	for i := 0; i < 20; i++ {
		resp, err := client.Get("http://unix/flags")
		if err == nil && resp.StatusCode == 200 {
			var flags []model.Flag
			if json.NewDecoder(resp.Body).Decode(&flags) == nil && len(flags) > 0 {
				flagFound = true
				resp.Body.Close()
				break
			}
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}

	if serverConn := <-connCh; serverConn != nil {
		serverConn.Close()
	}

	if !flagFound {
		events := st.RecentEvents(50)
		evData, _ := json.MarshalIndent(events, "", "  ")
		flags := st.RecentFlags(50)
		flData, _ := json.MarshalIndent(flags, "", "  ")
		t.Fatalf("E2E smoke scenario failed: flag was not triggered via API.\nEVENTS:\n%s\nFLAGS:\n%s", string(evData), string(flData))
	}
}
