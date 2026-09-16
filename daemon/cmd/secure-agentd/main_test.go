package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
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
	// Teardown order is load-bearing on every path (Fatalf included): the
	// consumer goroutine must be fully drained (bus closed + done) BEFORE the
	// store closes, or in-flight PutEvent/PutFlag calls write into a closed
	// database ("sql: database is closed" — seen as CI flake on Linux).
	t.Cleanup(func() { st.Close() })

	cfg, _ := config.Load("/nonexistent")
	b := bus.New(64)

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
	t.Cleanup(func() {
		b.Close()
		<-done
	})

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

	// The consumer goroutine processes the pair asynchronously; a fixed sleep
	// races the scheduler on slow/loaded runners (0 flags → spurious FAIL).
	// Poll the store until the flag lands or the deadline expires.
	var flags []model.Flag
	deadline := time.Now().Add(3 * time.Second)
	for {
		flags = st.RecentFlags(10)
		if len(flags) == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(flags) != 1 {
		t.Fatalf("expected 1 flag in store, got %d", len(flags))
	}
	if flags[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("rule = %s, want sensitive-read-then-connect", flags[0].Rule)
	}
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
	// Same teardown contract as the pipeline test above: drain the consumer
	// goroutine (bus closed + done) before the store closes, on every path.
	t.Cleanup(func() { st.Close() })

	b := bus.New(256)

	tg := agents.New(cfg, agents.NewProcSource())
	tg.Refresh()

	cl := sensitive.New(cfg)
	cr := correlate.New(tg, cl, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := b.Subscribe()
	consumerDone := make(chan struct{})
	go func() {
		for e := range sub {
			st.PutEvent(e)
			for _, fl := range cr.Observe(e) {
				st.PutFlag(fl)
			}
		}
		close(consumerDone)
	}()
	t.Cleanup(func() {
		b.Close()
		<-consumerDone
	})

	statusFn := func() api.Status { return api.Status{Running: true} }
	apiServer := api.New(sockPath, st, &realKiller{}, statusFn)
	serveErr := make(chan error, 1)
	go func() { serveErr <- apiServer.Serve(ctx) }()

	// Bind must finish before we poll /flags. A fixed 200ms sleep races
	// Serve on a loaded runner and the API loop expires while the store
	// already has the flag (false "not triggered via API").
	waitUnix(t, sockPath, 5*time.Second, serveErr)

	go supervise.Run(ctx, "netsample", func(c context.Context) error {
		ns := collect.NewNetSampler(b, tg, cfg.NetSampleInterval, nil)
		return ns.Run(c)
	})

	go supervise.Run(ctx, "transcript", func(c context.Context) error {
		ts := collect.NewTranscriptScanner(b, []string{actPath})
		return ts.Run(c)
	})

	// Simulate agent activity
	currPID := int32(os.Getpid()) // test process PID
	info, _ := agents.NewProcSource().Info(currPID)
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

	// Correlator writes asynchronously via netsample. Wait on the store
	// first (same contract as TestFullBusCorrelatorStorePipeline), then
	// assert the unix API serves the flag.
	deadline := time.Now().Add(5 * time.Second)
	for len(st.RecentFlags(10)) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(st.RecentFlags(10)) == 0 {
		events := st.RecentEvents(50)
		evData, _ := json.MarshalIndent(events, "", "  ")
		t.Fatalf("correlator never wrote a flag\nEVENTS:\n%s", string(evData))
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
		Timeout: 2 * time.Second,
	}

	var lastStatus int
	var lastErr error
	var lastBody string
	flagFound := false
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://unix/flags")
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastStatus = resp.StatusCode
		lastBody = string(body)
		if resp.StatusCode == http.StatusOK {
			var flags []model.Flag
			if err := json.Unmarshal(body, &flags); err != nil {
				lastErr = err
			} else if len(flags) > 0 {
				flagFound = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if serverConn := <-connCh; serverConn != nil {
		serverConn.Close()
	}

	if !flagFound {
		t.Fatalf("flag in store but /flags did not serve it: status=%d err=%v body=%s", lastStatus, lastErr, lastBody)
	}
}

func waitUnix(t *testing.T, path string, d time.Duration, serve <-chan error) {
	t.Helper()
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		select {
		case err := <-serve:
			t.Fatalf("api Serve exited before bind: %v", err)
		default:
		}
		c, err := net.Dial("unix", path)
		if err == nil {
			c.Close()
			return
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("unix socket %s never came up: %v", path, last)
}
