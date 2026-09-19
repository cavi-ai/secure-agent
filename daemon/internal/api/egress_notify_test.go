package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// The drill-down behind the posture warning: the operator clicks "N
// endpoints reached without inspection" and gets the actual list.
func TestUninspectedEgressEndpoint(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_test_egress_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, allowlistProcSource{})
	tg.Refresh()
	cr := correlate.New(tg, sensitive.New(cfg), cfg)

	now := time.Now()
	// Fresh endpoint (inside the window) and a stale one (outside it).
	cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: now.Add(-time.Hour), RemoteHost: "fresh.example.com", RemotePort: 443})
	cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: now.Add(-time.Hour), RemoteHost: "fresh.example.com", RemotePort: 443})
	cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: now.Add(-48 * time.Hour), RemoteHost: "stale.example.com", RemotePort: 443})

	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.correlator = cr
	a.allowlist = nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	get := func(path string) []UninspectedEndpoint {
		resp, err := cl.Get("http://unix" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: status %d", path, resp.StatusCode)
		}
		var out []UninspectedEndpoint
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return out
	}

	// Default 24h window: only the fresh endpoint, with its count.
	got := get("/egress/uninspected")
	if len(got) != 1 || got[0].Host != "fresh.example.com" || got[0].Count != 2 || got[0].Agent != "cursor" {
		t.Fatalf("default window wrong: %+v", got)
	}
	// Wider window reaches the stale endpoint too.
	got = get("/egress/uninspected?hours=168")
	if len(got) != 2 {
		t.Fatalf("168h window = %+v, want 2 endpoints", got)
	}
	// Nonsense hours fall back to the default instead of erroring.
	got = get("/egress/uninspected?hours=99999")
	if len(got) != 1 {
		t.Fatalf("out-of-range hours must fall back to 24h: %+v", got)
	}
}

func TestNotifyRulesEndpoint(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sa_test_notify_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	st := testStore(t)
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.notifyRules = correlate.NewNotifyRuleStore(filepath.Join(dir, "notify-rules.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	type payload struct {
		DefaultMinSeverity int             `json:"default_min_severity"`
		Overrides          map[string]bool `json:"overrides"`
	}
	get := func() payload {
		resp, err := cl.Get("http://unix/notify/rules")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var p payload
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	p := get()
	if p.DefaultMinSeverity != 3 || len(p.Overrides) != 0 {
		t.Fatalf("default policy wrong: %+v", p)
	}

	// Set a false override (never notify for this class).
	resp, err := cl.Post("http://unix/notify/rules", "application/json",
		strings.NewReader(`{"rule":"keychain-access","notify":false}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("set: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()
	p = get()
	if v, ok := p.Overrides["keychain-access"]; !ok || v != false {
		t.Fatalf("false override missing: %+v", p.Overrides)
	}

	// Invalid rule id rejected.
	resp, err = cl.Post("http://unix/notify/rules", "application/json",
		strings.NewReader(`{"rule":"bad rule!","notify":true}`))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid rule must be rejected: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Null clears the override.
	resp, err = cl.Post("http://unix/notify/rules", "application/json",
		strings.NewReader(`{"rule":"keychain-access","notify":null}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("clear: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()
	p = get()
	if _, ok := p.Overrides["keychain-access"]; ok {
		t.Fatal("cleared override must be gone")
	}

	// Sets and clears are audited.
	foundSet, foundClear := false, false
	for _, e := range st.RecentAudit(10) {
		if e.Action == "notify-rule-set" {
			foundSet = true
		}
		if e.Action == "notify-rule-clear" {
			foundClear = true
		}
	}
	if !foundSet || !foundClear {
		t.Fatalf("overrides must be audited (set=%v clear=%v)", foundSet, foundClear)
	}
}

// The on-demand host assessment: the console asks "what is this endpoint?"
// and gets a cached verdict plus a queued fresh assessment. This is the
// advisor functionality that turns a raw IP into a decision.
func TestAdvisorAssessHostEndpoint(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_assess_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	st := testStore(t)
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })

	queued := []string{}
	a.hostAssess = &HostAssessFuncs{
		GetVerdict: func(agent, host string) (model.AdvisorVerdict, bool) {
			if host == "known.example.com" {
				return model.AdvisorVerdict{Assessment: "benign", Rationale: "routine vendor traffic"}, true
			}
			return model.AdvisorVerdict{}, false
		},
		Enqueue: func(agent, host string) bool {
			queued = append(queued, agent+"|"+host)
			return true
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	post := func(body string) (int, map[string]any) {
		resp, err := cl.Post("http://unix/advisor/assess-host", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST assess-host: %v", err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	// Cached verdict path: answered immediately, still (re)queued.
	code, out := post(`{"agent":"cursor","host":"known.example.com"}`)
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	if v, ok := out["verdict"].(map[string]any); !ok || v["assessment"] != "benign" {
		t.Fatalf("cached verdict missing: %v", out)
	}
	if out["queued"] != true {
		t.Fatalf("queued = %v, want true", out["queued"])
	}

	// Unknown host: queued, no verdict yet.
	code, out = post(`{"agent":"codex","host":"2607:6bc0::10"}`)
	if code != 200 || out["queued"] != true {
		t.Fatalf("unknown host: code=%d out=%v", code, out)
	}
	if _, has := out["verdict"]; has {
		t.Fatalf("unknown host must not carry a verdict: %v", out)
	}
	if len(queued) != 2 {
		t.Fatalf("enqueued = %v, want 2", queued)
	}

	// Missing host is rejected.
	if code, _ := post(`{"agent":"x"}`); code != 400 {
		t.Fatalf("missing host: status = %d, want 400", code)
	}
}

// With no advisor wired, the endpoint is an honest 503 (the console renders
// "Advisor is off" rather than a dead button).
func TestAdvisorAssessHostDisabled(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_assess_off_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/advisor/assess-host", "application/json", strings.NewReader(`{"agent":"x","host":"y"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// Per-workspace notification scopes are the more specific tier over per-rule
// overrides: set/get/clear through the same endpoint, surfaced in GET.
func TestNotifyWorkspaceScopes(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_nscope_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	dir := t.TempDir()
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.notifyRules = correlate.NewNotifyRuleStore(filepath.Join(dir, "notify-rules.json"))
	a.notifyScopes = correlate.NewNotifyScopeStore(filepath.Join(dir, "notify-scopes.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	type payload struct {
		Scopes []correlate.NotifyScopePair `json:"scopes"`
	}
	get := func() payload {
		resp, err := cl.Get("http://unix/notify/rules")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var p payload
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if len(get().Scopes) != 0 {
		t.Fatal("expected no scopes initially")
	}
	resp, err := cl.Post("http://unix/notify/rules", "application/json",
		strings.NewReader(`{"workspace":"/Users/dev/prod","rule":"proxy-secret-leak","notify":true}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("set scope: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	scopes := get().Scopes
	if len(scopes) != 1 || scopes[0].Workspace != "/Users/dev/prod" || !scopes[0].Notify {
		t.Fatalf("scope not surfaced: %+v", scopes)
	}

	// Clear via null notify.
	resp, err = cl.Post("http://unix/notify/rules", "application/json",
		strings.NewReader(`{"workspace":"/Users/dev/prod","rule":"proxy-secret-leak","notify":null}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("clear scope: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()
	if len(get().Scopes) != 0 {
		t.Fatal("cleared scope still present")
	}
}

// /resources is downsampled: 720 sparkline points become <=120, always
// keeping the newest sample. The full series stays in the store for episodes.
func TestResourcesDownsamplesSamples(t *testing.T) {
	mk := func(n int) []resource.Sample {
		out := make([]resource.Sample, n)
		for i := range out {
			out[i] = resource.Sample{At: time.Now().Add(time.Duration(i) * time.Second), RSSBytes: uint64(i)}
		}
		return out
	}
	if got := downsample(mk(5), 120); len(got) != 5 {
		t.Fatalf("short series changed: %d", len(got))
	}
	got := downsample(mk(720), 120)
	if len(got) != 120 {
		t.Fatalf("downsampled = %d, want 120", len(got))
	}
	// The newest sample must survive (the UI labels it "now").
	if got[len(got)-1].RSSBytes != 719 {
		t.Fatalf("last sample = %d, want 719", got[len(got)-1].RSSBytes)
	}
}
