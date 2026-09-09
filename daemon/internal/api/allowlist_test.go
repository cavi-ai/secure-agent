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
	return []agents.ProcInfo{{PID: 42, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"}}
}

func (allowlistProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 42 {
		return agents.ProcInfo{PID: 42, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"}, true
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
	conn := event.Event{Kind: event.KindConnOpen, PID: 42, RemoteHost: "registry.npmjs.org", RemotePort: 443}
	for i := 0; i < minSuggestionCount-1; i++ {
		conn.TS = now.Add(time.Duration(i) * time.Second)
		cr.Observe(conn)
	}

	st := testStore(t)
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetAllowlist(cr, al)
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
	if len(got) != 1 || got[0].Host != "registry.npmjs.org" || got[0].Agent != "cursor" || got[0].Count != minSuggestionCount {
		t.Fatalf("suggestion wrong: %+v", got)
	}

	// Host with smuggled structure is rejected.
	resp, err := cl.Post("http://unix/allowlist", "application/json",
		strings.NewReader(`{"agent":"cursor","host":"evil.xyz/redirect"}`))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("structured host must be rejected: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Approve: persists, purges the blind spot, audits.
	resp, err = cl.Post("http://unix/allowlist", "application/json",
		strings.NewReader(`{"agent":"cursor","host":"registry.npmjs.org"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("approve: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	if hosts := al.Load()["cursor"]; len(hosts) != 1 || hosts[0] != "registry.npmjs.org" {
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
		if e.Action == "allowlist-add" && strings.Contains(e.Detail, "registry.npmjs.org") {
			found = true
		}
	}
	if !found {
		t.Fatal("approval must be audited")
	}
}
