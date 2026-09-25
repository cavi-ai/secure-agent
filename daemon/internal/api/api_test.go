package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type fakeKiller struct {
	killed int32
	all    []int32
}

func (f *fakeKiller) Kill(pid int32) error {
	f.killed = pid
	f.all = append(f.all, pid)
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
		// A loaded -race -shuffle run can stall a handler for seconds; a
		// hung handler still fails the test, only later.
		Timeout: 30 * time.Second,
	}
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			conn.Close()
			return
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s not ready: %v", socketPath, last)
}

func TestKillEndpointInvokesKiller(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	fk := &fakeKiller{}
	a := newTestAPI(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":7}`))
	if err != nil {
		t.Fatalf("kill post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
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

	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setFirewallForTest(FirewallControl{Engine: eng, Modes: modes})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/firewall/mode", "application/json", strings.NewReader(`{"rule":"aws-key","mode":"block"}`))
	if err != nil {
		t.Fatalf("firewall mode post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	if eng.RuleMode("aws-key") != firewall.ModeBlock {
		t.Fatal("rule was not promoted to block in the engine")
	}
	if modes.Load()["aws-key"] != "block" {
		t.Fatal("promotion was not persisted to the mode store")
	}
}

func TestFirewallModePromotesAllOfTypeLeavesOthers(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sa_test_fwtype_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	eng, err := firewall.NewEngine(config.FirewallConfig{
		Mode: "monitor",
		Patterns: []config.PatternConfig{
			{ID: "anthropic-key", Type: "vendor-key", Re: `sk-ant-[A-Za-z0-9_-]{24,}`, Mode: "monitor"},
			{ID: "openai-key", Type: "vendor-key", Re: `sk-[A-Za-z0-9]{32,}`, Mode: "monitor"},
			{ID: "aws-key", Type: "cloud-key", Re: `AKIA[0-9A-Z]{16}`, Mode: "monitor"},
		},
	}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	modes := firewall.NewModeStore(filepath.Join(dir, "firewall-modes.json"))

	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setFirewallForTest(FirewallControl{Engine: eng, Modes: modes})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/firewall/mode", "application/json", strings.NewReader(`{"type":"vendor-key","mode":"block"}`))
	if err != nil {
		t.Fatalf("firewall type post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"anthropic-key"`) || !strings.Contains(string(body), `"openai-key"`) {
		t.Fatalf("response missing promoted vendor-key ids: %s", body)
	}
	if eng.RuleMode("anthropic-key") != firewall.ModeBlock || eng.RuleMode("openai-key") != firewall.ModeBlock {
		t.Fatal("vendor-key rules were not promoted to block")
	}
	if eng.RuleMode("aws-key") != firewall.ModeMonitor {
		t.Fatal("cloud-key rule must stay in monitor")
	}
	loaded := modes.Load()
	if loaded["anthropic-key"] != "block" || loaded["openai-key"] != "block" {
		t.Fatalf("type promotion not persisted: %v", loaded)
	}
	if _, ok := loaded["aws-key"]; ok {
		t.Fatal("cloud-key must not be written to the mode store")
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
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	get := func(path string) string {
		resp, err := cl.Get("http://unix" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status=%v", resp.StatusCode)
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

	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setFirewallForTest(FirewallControl{Engine: eng, Modes: modes})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/firewall/mode", "application/json", strings.NewReader(`{"rule":"aws-key","mode":"block"}`))
	if err != nil {
		t.Fatalf("firewall mode post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
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
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setFirewallForTest(FirewallControl{
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
	if err != nil {
		t.Fatalf("ingest post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
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

	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setFirewallForTest(FirewallControl{
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
	sysResp, err := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(`{"source":"/etc/master.passwd","op":"add"}`))
	if err != nil {
		t.Fatalf("POST /firewall/sources: %v", err)
	}
	if sysResp.StatusCode != 400 {
		t.Fatalf("add of system path status=%d, want 400", sysResp.StatusCode)
	}

	// add the real source
	resp, err := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(fmt.Sprintf(`{"source":%q,"op":"add"}`, srcFile)))
	if err != nil {
		t.Fatalf("add post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	if ingestCalls != 1 {
		t.Fatalf("add should re-ingest once, got %d calls", ingestCalls)
	}

	// GET shows config (read-only) + the user source
	getResp, err := cl.Get("http://unix/firewall/sources")
	if err != nil {
		t.Fatalf("GET /firewall/sources: %v", err)
	}
	body, _ := io.ReadAll(getResp.Body)
	if !strings.Contains(string(body), `"source":"/etc/agent/defaults.env","origin":"config"`) {
		t.Fatalf("sources GET missing config source: %s", body)
	}
	if !strings.Contains(string(body), srcFile) || !strings.Contains(string(body), `"origin":"user"`) {
		t.Fatalf("sources GET missing user source %s: %s", srcFile, body)
	}

	// audit row carries the path
	auditResp, err := cl.Get("http://unix/audit")
	if err != nil {
		t.Fatalf("GET /audit: %v", err)
	}
	auditBody, _ := io.ReadAll(auditResp.Body)
	if !strings.Contains(string(auditBody), `"action":"source-add"`) || !strings.Contains(string(auditBody), srcFile) {
		t.Fatalf("audit missing source-add row with path: %s", auditBody)
	}

	// removing a config source is rejected
	badResp, err := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(`{"source":"/etc/agent/defaults.env","op":"remove"}`))
	if err != nil {
		t.Fatalf("POST /firewall/sources: %v", err)
	}
	if badResp.StatusCode != 400 {
		t.Fatalf("remove of config source status=%d, want 400", badResp.StatusCode)
	}

	// removing the user source succeeds and re-ingests again
	rmResp, err := cl.Post("http://unix/firewall/sources", "application/json", strings.NewReader(fmt.Sprintf(`{"source":%q,"op":"remove"}`, srcFile)))
	if err != nil {
		t.Fatalf("POST /firewall/sources: %v", err)
	}
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

func TestGuardPendingSortedByTSAscending(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	broker := guard.NewBroker(2 * time.Second)
	a.guardBroker = broker

	// Enqueue with explicit, out-of-order timestamps. The broker keys its
	// waiters by a map, which has no inherent order, so the handler must
	// sort explicitly rather than relying on iteration order.
	go broker.Request(guard.Pending{ID: "b", Agent: "claude", RuleID: "r2", TS: "2026-01-01T00:00:02Z"})
	go broker.Request(guard.Pending{ID: "a", Agent: "claude", RuleID: "r1", TS: "2026-01-01T00:00:01Z"})
	go broker.Request(guard.Pending{ID: "c", Agent: "claude", RuleID: "r3", TS: "2026-01-01T00:00:03Z"})

	deadline := time.Now().Add(2 * time.Second)
	for len(broker.Pending()) != 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(broker.Pending()); n != 3 {
		t.Fatalf("waiters registered = %d, want 3", n)
	}

	rr := httptest.NewRecorder()
	a.handleGuardPending(rr, httptest.NewRequest("GET", "/guard/pending", nil))
	var got []guard.Pending
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("pending count = %d, want 3: %+v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].TS > got[i].TS {
			t.Fatalf("pending not sorted ascending by ts: %+v", got)
		}
	}
	if got[0].ID != "a" || got[1].ID != "b" || got[2].ID != "c" {
		t.Fatalf("unexpected order: %+v", got)
	}

	// Resolve everything so the goroutines don't outlive the test.
	for _, p := range got {
		broker.Resolve(p.ID, guard.Decision{Verdict: "deny", Scope: "once"})
	}
}

func TestGuardDecisionCachedRule(t *testing.T) {
	st := testStore(t)
	st.PutGuardRule(store.GuardRule{Agent: "claude", RuleID: "cloud-creds", Decision: "allow", Source: "onboarding"})

	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.guardBroker = guard.NewBroker(time.Second)

	body := `{"agent":"claude","tool":"Read","path":"/Users/x/.aws/credentials","rule_id":"cloud-creds"}`
	rr := httptest.NewRecorder()
	a.handleGuardDecision(rr, httptest.NewRequest("POST", "/guard/decision", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	var d guard.Decision
	json.Unmarshal(rr.Body.Bytes(), &d)
	if d.Verdict != "allow" {
		t.Fatalf("cached decision = %+v, want allow", d)
	}
}

func TestGuardDecisionRejectsInvalidAgent(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.guardBroker = guard.NewBroker(time.Second)

	// A shell metacharacter in "agent" is exactly what a forged control-plane
	// call (see the hook's guard-control-network denial) would try to smuggle
	// through this field.
	body := `{"agent":"claude; rm -rf /","tool":"Read","path":"/x","rule_id":"cloud-creds"}`
	rr := httptest.NewRecorder()
	a.handleGuardDecision(rr, httptest.NewRequest("POST", "/guard/decision", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

func TestGuardRulesDeleteRejectsInvalidRuleID(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/guard/rules?agent=claude&rule_id=../../etc/passwd", nil)
	a.handleGuardRules(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

func TestSnapshotBundlesHotTelemetry(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	st.PutFlag(model.Flag{ID: "flag-a", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude", PID: 1, TS: now})
	st.PutEvent(event.Event{Kind: event.KindProxyHit, PID: 1, TS: now, Detail: "proxy-scan"})

	a := newTestAPI("", st, &fakeKiller{}, func() Status {
		return Status{Running: true, Version: "test", ActiveAgents: 1,
			Agents: []AgentSummary{{PID: 1, Name: "claude"}}}
	})

	rr := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rr, httptest.NewRequest("GET", "/snapshot", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /snapshot code=%d body=%s", rr.Code, rr.Body.String())
	}
	var snap struct {
		Status      Status          `json:"status"`
		Flags       []model.Flag    `json:"flags"`
		Events      []event.Event   `json:"events"`
		Posture     Posture         `json:"posture"`
		Mutes       []MutePair      `json:"mutes"`
		Suggestions []Suggestion    `json:"suggestions"`
		Incidents   json.RawMessage `json:"incidents"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode snapshot: %v body=%s", err, rr.Body.String())
	}
	if !snap.Status.Running || snap.Status.Version != "test" {
		t.Fatalf("status = %+v", snap.Status)
	}
	if len(snap.Flags) != 1 || snap.Flags[0].ID != "flag-a" {
		t.Fatalf("flags = %+v", snap.Flags)
	}
	if len(snap.Events) != 1 {
		t.Fatalf("events = %+v", snap.Events)
	}
	if snap.Mutes == nil {
		t.Fatal("mutes must be an array, not omitted")
	}
	if snap.Suggestions == nil {
		t.Fatal("suggestions must be an array, not omitted")
	}
	if snap.Incidents == nil {
		t.Fatal("incidents key missing")
	}
	if snap.Posture.Generated == "" {
		t.Fatal("posture not populated")
	}
	if snap.Status.UnactedFlags24h != 1 {
		t.Fatalf("unacted_flags_24h = %d, want 1", snap.Status.UnactedFlags24h)
	}
}

func TestStatusCountsUnacted24hAndBusDrops(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	st.PutFlag(model.Flag{ID: "fresh", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude", PID: 1, TS: now})
	st.PutFlag(model.Flag{ID: "old", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude", PID: 1, TS: now.Add(-48 * time.Hour)})
	st.PutFlag(model.Flag{ID: "ack", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude", PID: 1, TS: now})
	st.AcknowledgeFlag("ack")
	st.PutFlag(model.Flag{ID: "info", Rule: "keychain-access", Severity: 1, Agent: "claude", PID: 1, TS: now})

	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.busDrops = func() uint64 { return 7 }

	rr := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rr, httptest.NewRequest("GET", "/status", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /status code=%d", rr.Code)
	}
	var got Status
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.UnactedFlags24h != 1 {
		t.Fatalf("unacted_flags_24h = %d, want 1 (fresh sev>=2 only)", got.UnactedFlags24h)
	}
	if got.BusDrops != 7 {
		t.Fatalf("bus_drops = %d, want 7", got.BusDrops)
	}
}

func TestGroupAgentTreesOneRowPerRootHelpersFolded(t *testing.T) {
	trees := GroupAgentTrees([]AgentSummary{
		{PID: 5822, Name: "claude", RootPID: 5821, RSSBytes: 50, CPUPercent: 25, LastSeenAt: "2026-09-11T11:00:00Z"},
		{PID: 5821, Name: "claude", CWD: "/Users/dev/workspace/api-service", RootPID: 5821, RSSBytes: 100, CPUPercent: 50, LastSeenAt: "2026-09-11T12:00:00Z"},
		{PID: 6033, Name: "cursor", CWD: "/Users/dev/projects/web-app", RootPID: 6033, RSSBytes: 10, LastSeenAt: "2026-09-11T11:00:00Z"},
	})
	if len(trees) != 2 {
		t.Fatalf("trees = %d, want 2", len(trees))
	}
	if trees[0].Root.PID != 5821 {
		t.Fatalf("first root = %d, want 5821 (most recent last_seen)", trees[0].Root.PID)
	}
	if trees[0].RSSBytes != 150 {
		t.Fatalf("family rss = %d, want 150", trees[0].RSSBytes)
	}
	if trees[0].CPUPercent != 75 {
		t.Fatalf("family cpu = %v, want 75", trees[0].CPUPercent)
	}
	if len(trees[0].Children) != 1 || trees[0].Children[0].PID != 5822 {
		t.Fatalf("children = %+v, want helper 5822", trees[0].Children)
	}
	if trees[1].Root.PID != 6033 || len(trees[1].Children) != 0 {
		t.Fatalf("second tree = %+v", trees[1])
	}
}

func TestStatusJSONIncludesTrees(t *testing.T) {
	db := testStore(t)
	now := time.Now()
	db.UpsertSession(model.Session{ID: "s-origin", Harness: "claude", RootPID: 10, Repo: "career-ops", Branch: "main",
		Origin: "martina (openclaw)", StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfProcessTree})
	a := newTestAPI("", db, &fakeKiller{}, func() Status {
		return Status{Running: true, Agents: []AgentSummary{
			{PID: 10, Name: "claude", RootPID: 10, CPUPercent: 60},
			{PID: 11, Name: "claude", RootPID: 10, CPUPercent: 15},
		}}
	})
	rr := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rr, httptest.NewRequest("GET", "/status", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /status code=%d", rr.Code)
	}
	var st Status
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Trees) != 1 || st.Trees[0].Root.PID != 10 || len(st.Trees[0].Children) != 1 {
		t.Fatalf("trees = %+v", st.Trees)
	}
	if st.Agents[0].CPUPercent != 60 || st.Trees[0].CPUPercent != 75 {
		t.Fatalf("CPU serialization/aggregation failed: agents=%+v trees=%+v", st.Agents, st.Trees)
	}
	// The root joins its session by root pid, the spawning agent included.
	if r := st.Trees[0].Root; r.SessionID != "s-origin" || r.Repo != "career-ops" || r.Origin != "martina (openclaw)" {
		t.Fatalf("tree root join = %+v, want session s-origin, repo career-ops, origin martina (openclaw)", r)
	}
	if !strings.Contains(rr.Body.String(), `"origin":"martina (openclaw)"`) {
		t.Fatalf("/status body carries no root origin: %s", rr.Body.String())
	}
}

func TestKillEndpointKillsTaggedTreeSharingRootPID(t *testing.T) {
	fk := &fakeKiller{}
	a := newTestAPI("", testStore(t), fk, func() Status {
		return Status{Running: true, Agents: []AgentSummary{
			{PID: 10, Name: "claude", RootPID: 10},
			{PID: 11, Name: "claude", RootPID: 10},
			{PID: 12, Name: "claude", RootPID: 10},
			{PID: 20, Name: "cursor", RootPID: 20},
		}}
	})
	req := httptest.NewRequest(http.MethodPost, "/kill", strings.NewReader(`{"pid":10}`))
	rec := httptest.NewRecorder()
	a.handleKill(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	got := map[int32]int{}
	for _, p := range fk.all {
		got[p]++
	}
	for _, want := range []int32{10, 11, 12} {
		if got[want] != 1 {
			t.Fatalf("killed %v, want tree 10,11,12 once each", fk.all)
		}
	}
	if got[20] != 0 {
		t.Fatalf("killed other tree pid 20: %v", fk.all)
	}
	if len(fk.all) != 3 {
		t.Fatalf("killed %v, want exactly 3 pids", fk.all)
	}
}

func TestKillEndpointHelperPIDKillsWholeTree(t *testing.T) {
	fk := &fakeKiller{}
	a := newTestAPI("", testStore(t), fk, func() Status {
		return Status{Running: true, Agents: []AgentSummary{
			{PID: 10, Name: "claude", RootPID: 10},
			{PID: 11, Name: "claude", RootPID: 10},
			{PID: 12, Name: "claude", RootPID: 10},
		}}
	})
	req := httptest.NewRequest(http.MethodPost, "/kill", strings.NewReader(`{"pid":11}`))
	rec := httptest.NewRecorder()
	a.handleKill(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	got := map[int32]int{}
	for _, p := range fk.all {
		got[p]++
	}
	for _, want := range []int32{10, 11, 12} {
		if got[want] != 1 {
			t.Fatalf("helper kill %v, want whole tree 10,11,12", fk.all)
		}
	}
}

func TestTerminateAgentTreeUsesLiveHelperWhenRootExited(t *testing.T) {
	fk := &fakeKiller{}
	started := "2026-09-09T16:00:00.123456789Z"
	a := newTestAPI("", testStore(t), fk, func() Status {
		return Status{Running: true, Agents: []AgentSummary{
			{PID: 11, Name: "claude", RootPID: 10, StartedAt: started, IsOrphan: true},
			{PID: 12, Name: "claude", RootPID: 10, IsOrphan: true},
		}}
	})
	a.agentPIDs = func() map[int32]struct{} { return map[int32]struct{}{11: {}, 12: {}} }
	if a.peerRole != nil {
		a.peerRole.AgentPIDs = func() map[int32]struct{} { return map[int32]struct{}{11: {}, 12: {}} }
	}
	killed, err := a.TerminateAgentTree(11, started)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(killed, []int32{11, 12}) {
		t.Fatalf("killed=%v want [11 12]", killed)
	}
}

func TestTerminateAgentTreeVerifiedRejectsReusedChildPID(t *testing.T) {
	fk := &fakeKiller{}
	rootStarted := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	childStarted := rootStarted.Add(time.Second)
	a := newTestAPI("", testStore(t), fk, func() Status {
		return Status{Running: true, Agents: []AgentSummary{
			{PID: 10, Name: "claude", RootPID: 10, StartedAt: rootStarted.Format(time.RFC3339Nano)},
			{PID: 11, Name: "claude", RootPID: 10, StartedAt: childStarted.Add(time.Second).Format(time.RFC3339Nano)},
		}}
	})
	a.agentPIDs = func() map[int32]struct{} { return map[int32]struct{}{10: {}, 11: {}} }
	if a.peerRole != nil {
		a.peerRole.AgentPIDs = func() map[int32]struct{} { return map[int32]struct{}{10: {}, 11: {}} }
	}
	_, err := a.TerminateAgentTreeVerified(10, rootStarted.Format(time.RFC3339Nano), map[int32]time.Time{
		10: rootStarted,
		11: childStarted,
	})
	if err == nil {
		t.Fatal("reused child pid was accepted")
	}
	if len(fk.all) != 0 {
		t.Fatalf("killed=%v before family identity validation completed", fk.all)
	}
}

// /sessions serves the durable session spine: live and ended, newest first.
func TestSessionsEndpoint(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_sessions_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Workspace: "/repo", Repo: "repo", Branch: "main",
		StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfHook})
	st.UpsertSession(model.Session{ID: "s2", Harness: "codex", StartedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-time.Hour),
		Status: model.SessionActive, Confidence: model.ConfProcessTree})
	st.EndSession("s2", now.Add(-30*time.Minute))

	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)

	resp, err := cl.Get("http://unix/sessions")
	if err != nil {
		t.Fatalf("GET /sessions: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	var all []model.Session
	decodeInto(t, resp, &all)
	if len(all) != 2 {
		t.Fatalf("sessions = %d, want 2 (live + ended)", len(all))
	}
	if all[0].ID != "s1" || all[0].Repo != "repo" || all[0].Branch != "main" {
		t.Fatalf("first session = %+v, want the live hook session with metadata", all[0])
	}
	if all[1].ID != "s2" || all[1].EndedAt == nil {
		t.Fatalf("second session = %+v, want ended with ended_at", all[1])
	}

	resp2, err := cl.Get("http://unix/sessions?status=ended")
	if err != nil {
		t.Fatalf("GET /sessions?status=ended: %v", err)
	}
	var ended []model.Session
	decodeInto(t, resp2, &ended)
	if len(ended) != 1 || ended[0].ID != "s2" {
		t.Fatalf("status=ended = %+v, want only s2", ended)
	}
}

// /sessions/{id}/timeline serves one session's events oldest-first.
func TestSessionTimelineEndpoint(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_timeline_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	now := time.Now()
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now, SessionID: "s1", Model: "claude-sonnet-4-5", TokensIn: 100, TokensOut: 10})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now.Add(time.Second), SessionID: "s1", ToolName: "Bash", ToolStatus: "ok", DurationMs: 900})
	st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now.Add(2 * time.Second), SessionID: "other", Path: "/x"})

	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/sessions/s1/timeline")
	if err != nil {
		t.Fatalf("GET timeline: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	var tl []event.Event
	decodeInto(t, resp, &tl)
	if len(tl) != 2 {
		t.Fatalf("timeline = %d events, want 2 (other session excluded)", len(tl))
	}
	if tl[0].Kind != event.KindModelCall || tl[1].Kind != event.KindToolCall {
		t.Fatalf("timeline not oldest-first: %v, %v", tl[0].Kind, tl[1].Kind)
	}
	if tl[0].TokensIn != 100 || tl[1].DurationMs != 900 || tl[1].ToolName != "Bash" {
		t.Fatalf("trace fields lost: %+v %+v", tl[0], tl[1])
	}

	resp2, err := cl.Get("http://unix/sessions/s1")
	if err != nil {
		t.Fatalf("GET /sessions/s1: %v", err)
	}
	if resp2.StatusCode != 404 {
		t.Fatalf("GET /sessions/s1 without subpath: %d, want 404", resp2.StatusCode)
	}
	resp2.Body.Close()
}

// A session's origin round-trips through /sessions, the session report and
// /snapshot; a session without one serves none.
func TestSessionOriginServed(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	st.UpsertSession(model.Session{ID: "oc", Harness: "codex", Origin: "martina (openclaw)",
		StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfTranscript})
	st.UpsertSession(model.Session{ID: "own", Harness: "codex",
		StartedAt: now.Add(-time.Minute), LastSeenAt: now.Add(-time.Minute), Status: model.SessionActive, Confidence: model.ConfTranscript})
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	get := func(path string, into any) string {
		t.Helper()
		rr := httptest.NewRecorder()
		a.buildMux().ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 {
			t.Fatalf("GET %s code=%d", path, rr.Code)
		}
		if err := json.Unmarshal(rr.Body.Bytes(), into); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return rr.Body.String()
	}
	origins := func(l []model.Session) map[string]string {
		m := map[string]string{}
		for _, s := range l {
			m[s.ID] = s.Origin
		}
		return m
	}
	var list []model.Session
	body := get("/sessions", &list)
	if o := origins(list); o["oc"] != "martina (openclaw)" || o["own"] != "" {
		t.Fatalf("/sessions origins = %v", o)
	}
	if strings.Count(body, `"origin"`) != 1 {
		t.Fatalf("/sessions: want origin on exactly one row (omitempty), body has %d", strings.Count(body, `"origin"`))
	}
	var rep struct {
		Session model.Session `json:"session"`
	}
	get("/sessions/oc/report?format=json", &rep)
	if rep.Session.Origin != "martina (openclaw)" {
		t.Fatalf("report session origin = %q", rep.Session.Origin)
	}
	var snap struct {
		Sessions []model.Session `json:"sessions"`
	}
	get("/snapshot", &snap)
	if o := origins(snap.Sessions); o["oc"] != "martina (openclaw)" || o["own"] != "" {
		t.Fatalf("/snapshot origins = %v", o)
	}
}
