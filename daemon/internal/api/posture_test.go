package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func TestPostureAllClearWhenNothingPending(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/posture")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("posture get: %v status=%v", err, resp.StatusCode)
	}
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "all-clear" || p.NeedsYou != 0 {
		t.Fatalf("posture = %+v, want all-clear/0", p)
	}
}

// A reviewed (acknowledged) flag must not keep demanding attention in the
// posture headline — dismiss has to actually close the loop.
func TestPostureExcludesAcknowledgedFlags(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture3_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	st.PutFlag(model.Flag{ID: "open-1", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), Evidence: []string{"read .env then connected"}})
	st.PutFlag(model.Flag{ID: "done-1", Rule: "proxy-secret-leak", Severity: 3, TS: time.Now(), Evidence: []string{"key in body"}})
	st.AcknowledgeFlag("done-1")
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.NeedsYou != 1 {
		t.Fatalf("posture = %+v, want exactly 1 item (the acknowledged flag must not count)", p)
	}
	for _, it := range p.Items {
		if it.ID == "done-1" {
			t.Fatal("acknowledged flag must not appear in posture items")
		}
	}
}

func TestPostureCriticalFlagDrivesState(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture2_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	st.PutFlag(model.Flag{ID: "f1", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), Evidence: []string{"read .env then connected"}})
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "critical" || p.NeedsYou != 1 {
		t.Fatalf("posture = %+v, want critical/1", p)
	}
	if p.Items[0].Title != "Agent read a secret, then connected out" {
		t.Fatalf("title = %q, want human phrasing", p.Items[0].Title)
	}
	if p.Summary == "" {
		t.Fatal("summary must be populated")
	}
}

func TestPostureCountsUninspectedEgressAndDeadCollectors(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture3_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status {
		return Status{
			Running:           true,
			UninspectedEgress: 3,
			Collectors:        []supervise.Health{{Name: "eslogger", Running: false, LastError: "exit 1"}},
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "attention" || p.NeedsYou != 2 {
		t.Fatalf("posture = %+v, want attention/2", p)
	}
	kinds := map[string]bool{}
	for _, it := range p.Items {
		kinds[it.Kind] = true
	}
	if !kinds["uninspected_egress"] || !kinds["collector_down"] {
		t.Fatalf("expected egress + collector items, got %+v", p.Items)
	}
	var egressTitle string
	for _, it := range p.Items {
		if it.Kind == "uninspected_egress" {
			egressTitle = it.Title
		}
	}
	if !strings.Contains(egressTitle, "3 connections") {
		t.Fatalf("egress title = %q", egressTitle)
	}
	// Collector items read as operator language, not process jargon.
	var collItem *PostureItem
	for i := range p.Items {
		if p.Items[i].Kind == "collector_down" {
			collItem = &p.Items[i]
		}
	}
	if collItem == nil {
		t.Fatal("missing collector_down item")
	}
	if collItem.Title != "File monitoring is off" {
		t.Fatalf("collector title = %q, want plain language", collItem.Title)
	}
	if !strings.Contains(collItem.Detail, "Full Disk Access") {
		t.Fatalf("collector detail should hint the fix, got %q", collItem.Detail)
	}
	if strings.Contains(p.Summary, "item(s)") {
		t.Fatalf("summary must not use lazy pluralization: %q", p.Summary)
	}
}

// A running collector that produces nothing while agents are active is the
// monitor's worst failure mode: green lights, blind sensors (the audit found
// both the eslogger spool and the hook pipeline dead for days, all healthy).
func TestPostureFlagsSilentCollectorsAndUncoveredHarnesses(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture5_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status {
		return Status{
			Running: true, Uptime: "1h0m0s", ActiveAgents: 2,
			Collectors: []supervise.Health{
				{Name: "eslogger", Running: true},   // never produced → silent
				{Name: "netsampler", Running: true}, // not watched (idle agents open no sockets)
			},
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)

	kinds := map[string]string{}
	for _, it := range p.Items {
		kinds[it.Kind] = it.ID
	}
	if kinds["collector_silent"] != "eslogger" {
		t.Fatalf("expected collector_silent for eslogger, got %+v", p.Items)
	}
	if kinds["harness_uncovered"] == "" {
		t.Fatalf("expected harness_uncovered (agents active, zero hook events), got %+v", p.Items)
	}
	for _, it := range p.Items {
		if it.Kind == "collector_silent" && it.ID == "netsampler" {
			t.Fatal("netsampler silence is ambiguous — it must not be flagged")
		}
	}
}

// No agents running: an idle machine is not a blind monitor — silence is
// legitimate, posture stays all-clear.
func TestPostureNoSilenceFlagsWhenIdle(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture6_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status {
		return Status{
			Running: true, Uptime: "2h0m0s", ActiveAgents: 0,
			Collectors: []supervise.Health{{Name: "eslogger", Running: true}},
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.NeedsYou != 0 {
		t.Fatalf("idle machine must be all-clear, got %+v", p.Items)
	}
}

func TestPostureOldFlagsDoNotCount(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture4_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	st.PutFlag(model.Flag{ID: "old", Rule: "keychain-access", Severity: 3, TS: time.Now().Add(-48 * time.Hour)})
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.NeedsYou != 0 {
		t.Fatalf("48h-old flag counted: %+v", p)
	}
}

// decodeInto is a tiny helper so tests stay flat.
func decodeInto(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := jsonDecode(resp.Body, v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// Transcript hits must NOT clear harness_uncovered: a secret pattern in any
// tailed log says nothing about whether the guard hook is registered. The old
// behaviour cleared on transcript hits, hiding the exact failure the item
// exists to report.
func TestHarnessUncoveredIgnoresTranscriptHits(t *testing.T) {
	st := testStore(t)
	st.PutEvent(event.Event{Kind: event.KindTranscriptHit, TS: time.Now(), Detail: "aws-key"})
	item := harnessUncoveredItem(st, Status{ActiveAgents: 2})
	if item == nil {
		t.Fatal("transcript hit must not clear harness_uncovered")
	}
	// A real hook action DOES clear it.
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: time.Now(), Detail: "Read"})
	if item := harnessUncoveredItem(st, Status{ActiveAgents: 2}); item != nil {
		t.Fatalf("plugin action should clear harness_uncovered, got %+v", item)
	}
}

// The guard-hook registration item is independent of transcript coverage: it
// reports a missing settings.json entry while agents are active.
func TestGuardHookUnregisteredItem(t *testing.T) {
	// No agents → nothing to say.
	if item := guardHookUnregisteredItem(Status{ActiveAgents: 0}); item != nil {
		t.Fatalf("no agents must not raise the item: %+v", item)
	}
	// With agents active and no (or unregistered) settings.json, it fires.
	item := guardHookUnregisteredItem(Status{ActiveAgents: 3})
	if item == nil {
		t.Fatal("expected guard_hook_unregistered when no hook is registered")
	}
	if item.Kind != "guard_hook_unregistered" || item.Severity != 2 {
		t.Fatalf("item = %+v", item)
	}
}

func TestClaudeHookRegistered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// Missing file → not registered.
	if claudeHookRegistered(path) {
		t.Fatal("missing settings.json must read as unregistered")
	}
	// Only PreToolUse → not fully registered.
	os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"python3 ~/.claude/hooks/secret_guard.py"}]}]}}`), 0o600)
	if claudeHookRegistered(path) {
		t.Fatal("PreToolUse alone must not count as registered")
	}
	// Both events → registered.
	os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"python3 ~/.claude/hooks/secret_guard.py"}]}],"PostToolUse":[{"hooks":[{"command":"python3 ~/.claude/hooks/secret_guard.py"}]}]}}`), 0o600)
	if !claudeHookRegistered(path) {
		t.Fatal("both events registered must read as registered")
	}
}
