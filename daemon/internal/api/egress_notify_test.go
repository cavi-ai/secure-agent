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

	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetAllowlist(cr, nil)
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
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetNotifyRules(correlate.NewNotifyRuleStore(filepath.Join(dir, "notify-rules.json")))
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
