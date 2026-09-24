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

type allowlistProcSource struct{}

func (allowlistProcSource) List() []agents.ProcInfo {
	return []agents.ProcInfo{{PID: 42, PPID: 1, Exe: "/usr/local/bin/cursor-agent"}}
}

func (allowlistProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 42 {
		return agents.ProcInfo{PID: 42, PPID: 1, Exe: "/usr/local/bin/cursor-agent"}, true
	}
	return agents.ProcInfo{}, false
}

func TestAllowlistSuggestApproveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sa_test_allowlist_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, allowlistProcSource{})
	tg.Refresh()
	cr := correlate.New(tg, sensitive.New(cfg), cfg)
	al := correlate.NewAllowlistStore(filepath.Join(dir, "allowlist-overrides.json"))
	cr.SetAllowlistOverrides(func(agent string) []string { return al.Load()[agent] })

	// Recurring uninspected egress: below threshold = no suggestion.
	now := time.Now()
	conn := event.Event{Kind: event.KindConnOpen, PID: 42, RemoteHost: "downloads.example.com", RemotePort: 443}
	for i := 0; i < minSuggestionCount-1; i++ {
		conn.TS = now.Add(time.Duration(i) * time.Second)
		cr.Observe(conn)
	}

	st := testStore(t)
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.correlator = cr
	a.allowlist = al
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	get := func(path string) []Suggestion {
		resp, err := cl.Get("http://unix" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		var out []Suggestion
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return out
	}

	if got := get("/allowlist/suggestions"); len(got) != 0 {
		t.Fatalf("below-threshold host must not be suggested: %v", got)
	}

	// Cross the threshold.
	conn.TS = now.Add(minSuggestionCount * time.Second)
	cr.Observe(conn)
	got := get("/allowlist/suggestions")
	if len(got) != 1 || got[0].Host != "downloads.example.com" || got[0].Agent != "cursor" || got[0].Count != minSuggestionCount {
		t.Fatalf("suggestion wrong: %+v", got)
	}

	// Host with smuggled structure is rejected.
	resp, err := cl.Post("http://unix/allowlist", "application/json",
		strings.NewReader(`{"agent":"cursor","host":"evil.xyz/redirect"}`))
	if err != nil {
		t.Fatalf("structured host must be rejected: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	resp.Body.Close()

	// Approve: persists, purges the blind spot, audits.
	resp, err = cl.Post("http://unix/allowlist", "application/json",
		strings.NewReader(`{"agent":"cursor","host":"downloads.example.com"}`))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	resp.Body.Close()

	if hosts := al.Load()["cursor"]; len(hosts) != 1 || hosts[0] != "downloads.example.com" {
		t.Fatalf("override not persisted: %v", hosts)
	}
	if got := get("/allowlist/suggestions"); len(got) != 0 {
		t.Fatalf("approved host must leave the suggestion list: %v", got)
	}
	if cr.UninspectedEgressCount() != 0 {
		t.Fatal("approved host must leave the blind-spot count")
	}
	audit := st.RecentAudit(10)
	found := false
	for _, e := range audit {
		if e.Action == "allowlist-add" && strings.Contains(e.Detail, "downloads.example.com") {
			found = true
		}
	}
	if !found {
		t.Fatal("approval must be audited")
	}
}

func TestMuteEndpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sa_test_mute_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, allowlistProcSource{})
	tg.Refresh()
	cr := correlate.New(tg, sensitive.New(cfg), cfg)
	ms := correlate.NewMuteStore(filepath.Join(dir, "muted.json"))
	cr.SetMuteChecker(ms.Muted)

	st := testStore(t)
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.correlator = cr
	a.mutes = ms
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	// Structured host rejected.
	resp, err := cl.Post("http://unix/mute", "application/json", strings.NewReader(`{"rule":"r","host":"evil.xyz/x"}`))
	if err != nil {
		t.Fatalf("structured host must 400: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("%v", resp.StatusCode)
	}
	resp.Body.Close()

	// Mute → listed → suppression is live → DELETE removes.
	resp, err = cl.Post("http://unix/mute", "application/json",
		strings.NewReader(`{"rule":"proxy-prompt-injection","host":"blog.example.com"}`))
	if err != nil {
		t.Fatalf("mute post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("%v", resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = cl.Get("http://unix/mute")
	if err != nil {
		t.Fatal(err)
	}
	var pairs []MutePair
	json.NewDecoder(resp.Body).Decode(&pairs)
	resp.Body.Close()
	if len(pairs) != 1 || pairs[0].Rule != "proxy-prompt-injection" || pairs[0].Host != "blog.example.com" {
		t.Fatalf("mute list = %v", pairs)
	}

	m := ms.Load()
	if len(m["proxy-prompt-injection"]) != 1 {
		t.Fatalf("store = %v", m)
	}

	req, _ := http.NewRequest(http.MethodDelete, "http://unix/mute?rule=proxy-prompt-injection&host=blog.example.com", nil)
	resp, err = cl.Do(req)
	if err != nil {
		t.Fatalf("unmute: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("%v", resp.StatusCode)
	}
	resp.Body.Close()
	if len(ms.Load()) != 0 {
		t.Fatal("unmute must empty the store")
	}
	// Both directions audited.
	var muteAdd, muteDel bool
	for _, e := range st.RecentAudit(10) {
		if e.Action == "mute-add" {
			muteAdd = true
		}
		if e.Action == "mute-remove" {
			muteDel = true
		}
	}
	if !muteAdd || !muteDel {
		t.Fatalf("mute lifecycle must be audited: %+v", st.RecentAudit(10))
	}
}

// Approvals are reversible: GET lists current overrides, DELETE removes one.
// A allowlist that only grows is a ratchet, not a policy.
func TestAllowlistListAndRemove(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sa_test_allowrm_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tagger := agents.New(cfg, allowlistProcSource{})
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg)
	alStore := correlate.NewAllowlistStore(filepath.Join(dir, "allow.json"))

	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.correlator = cr
	a.allowlist = alStore
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	post := func(method, body string) *http.Response {
		req, _ := http.NewRequest(method, "http://unix/allowlist", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	post(http.MethodPost, `{"agent":"cursor","host":"registry.npmjs.org"}`).Body.Close()
	post(http.MethodPost, `{"agent":"cursor","host":"example.com"}`).Body.Close()
	post(http.MethodPost, `{"agent":"claude","host":"cdn.anthropic.com"}`).Body.Close()

	// GET lists all three, sorted by agent then host.
	resp, err := cl.Get("http://unix/allowlist")
	if err != nil {
		t.Fatalf("GET /allowlist: %v", err)
	}
	var got []struct {
		Agent string `json:"agent"`
		Host  string `json:"host"`
	}
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if len(got) != 3 || got[0].Agent != "claude" || got[1].Host != "example.com" {
		t.Fatalf("GET /allowlist = %+v", got)
	}

	// DELETE removes exactly one pair.
	post(http.MethodDelete, `{"agent":"cursor","host":"example.com"}`).Body.Close()
	resp2, err := cl.Get("http://unix/allowlist")
	if err != nil {
		t.Fatalf("GET /allowlist: %v", err)
	}
	got = nil
	json.NewDecoder(resp2.Body).Decode(&got)
	resp2.Body.Close()
	if len(got) != 2 {
		t.Fatalf("after DELETE: %+v", got)
	}
	for _, p := range got {
		if p.Host == "example.com" {
			t.Fatalf("removed host still present: %+v", got)
		}
	}

	// Removing the last host of an agent drops the agent key entirely.
	post(http.MethodDelete, `{"agent":"claude","host":"cdn.anthropic.com"}`).Body.Close()
	m := alStore.Load()
	if _, ok := m["claude"]; ok {
		t.Fatalf("empty agent key should be dropped: %v", m)
	}

	// The removals are audited.
	aud := st.RecentAudit(10)
	found := 0
	for _, e := range aud {
		if e.Action == "allowlist-remove" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("allowlist-remove audit entries = %d, want 2", found)
	}
}

// IPv6 endpoints must be approvable: agents reach IPv6-only hosts and the
// suggestions list surfaces them, but the old validator rejected any ':' so
// the Allow button 400'd with no explanation ("nothing happens on click").
func TestValidAllowlistHost(t *testing.T) {
	ok := []string{
		"example.com", "sub.example.com", "15.133.36.34.bc.googleusercontent.com",
		"2607:6bc0::10", "2600:1900:4110:86f::", "2603:1030:10:d::4c3",
		"::1", "fe80::1", "127.0.0.1", "10.0.0.1",
	}
	for _, h := range ok {
		if !validAllowlistHost(h) {
			t.Errorf("%q should be allowed", h)
		}
	}
	bad := []string{
		"", "http://evil.com", "evil.com/path", "evil.com:443", "user@evil.com",
		"[::1]", "::1%en0", "a..b", "-lead.com", "trail-.com", "evil.com?x=1",
	}
	for _, h := range bad {
		if validAllowlistHost(h) {
			t.Errorf("%q should be rejected", h)
		}
	}
}
