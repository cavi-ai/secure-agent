package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func TestDismissPushesAllClearPosture(t *testing.T) {
	for _, body := range []string{`{"flag_id":"last"}`, `{"flag_ids":["last"]}`} {
		t.Run(body, func(t *testing.T) {
			st := testStore(t)
			st.PutFlag(model.Flag{ID: "last", Rule: "transcript-secret-leak", Severity: 2, TS: time.Now()})
			a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
			a.deltaHub = NewDeltaHub()
			ch := a.deltaHub.Subscribe()
			defer a.deltaHub.Unsubscribe(ch)
			a.PublishPostureIfChanged()
			<-ch
			w := httptest.NewRecorder()
			a.buildMux().ServeHTTP(w, httptest.NewRequest("POST", "/flags/acknowledge", strings.NewReader(body)))
			if w.Code != 200 {
				t.Fatalf("dismiss: %d", w.Code)
			}
			select {
			case d := <-ch:
				p, ok := d.Data.(Posture)
				if d.Type != "posture" || !ok || p.State != "all-clear" || p.NeedsYou != 0 {
					t.Fatalf("delta=%+v", d)
				}
			default:
				t.Fatal("dismiss left the menu bar waiting for a poll; no all-clear push")
			}
		})
	}
}

func TestPostureAllClearWhenNothingPending(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("posture get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
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
	st.PutFlag(model.Flag{ID: "open-1", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), Evidence: model.EvidenceFromStrings("read .env then connected")})
	st.PutFlag(model.Flag{ID: "done-1", Rule: "proxy-secret-leak", Severity: 3, TS: time.Now(), Evidence: model.EvidenceFromStrings("key in body")})
	st.AcknowledgeFlag("done-1")
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("GET /posture: %v", err)
	}
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
	st.PutFlag(model.Flag{ID: "f1", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), Evidence: model.EvidenceFromStrings("read .env then connected")})
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("GET /posture: %v", err)
	}
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "critical" || p.NeedsYou != 1 {
		t.Fatalf("posture = %+v, want critical/1", p)
	}
	if p.Items[0].Title != "Sensitive file read near an outside connection" {
		t.Fatalf("title = %q, want human phrasing", p.Items[0].Title)
	}
	if p.Summary == "" {
		t.Fatal("summary must be populated")
	}
}

// Uninspected egress alone is a coverage note: posture stays all-clear (the
// menu bar purple, no hero) and the note stays listed for the console.
func TestPostureEgressNoteAloneIsAllClear(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status {
		return Status{Running: true, UninspectedEgress: 9}
	})
	p := a.computePosture()
	if p.State != "all-clear" || p.NeedsYou != 0 || p.CoverageCount != 1 || p.CoverageItems[0].Kind != "uninspected_egress" {
		t.Fatalf("posture = %+v, want all-clear with the egress note listed", p)
	}
	if p.Summary != "All clear — agents monitored, no action needed." {
		t.Fatalf("summary = %q", p.Summary)
	}
}

func TestPostureSeparatesUninspectedEgressAndDeadCollectorsFromDecisions(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture3_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status {
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
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("GET /posture: %v", err)
	}
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "attention" || p.NeedsYou != 0 || p.CoverageCount != 2 {
		t.Fatalf("posture = %+v, want attention with 0 decisions and 2 coverage gaps", p)
	}
	kinds := map[string]bool{}
	for _, it := range p.CoverageItems {
		kinds[it.Kind] = true
	}
	if !kinds["uninspected_egress"] || !kinds["collector_down"] {
		t.Fatalf("expected egress + collector coverage, got %+v", p.CoverageItems)
	}
	var egressTitle string
	for _, it := range p.CoverageItems {
		if it.Kind == "uninspected_egress" {
			egressTitle = it.Title
		}
	}
	if !strings.Contains(egressTitle, "3 connections") {
		t.Fatalf("egress title = %q", egressTitle)
	}
	// Collector items read as operator language, not process jargon.
	var collItem *PostureItem
	for i := range p.CoverageItems {
		if p.CoverageItems[i].Kind == "collector_down" {
			collItem = &p.CoverageItems[i]
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
// monitor's worst failure mode: green lights, blind sensors.
func TestPostureFlagsSilentCollectorsAndUncoveredHarnesses(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture5_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status {
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
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("GET /posture: %v", err)
	}
	var p Posture
	decodeInto(t, resp, &p)

	kinds := map[string]string{}
	for _, it := range p.CoverageItems {
		kinds[it.Kind] = it.ID
	}
	if kinds["collector_silent"] != "eslogger" {
		t.Fatalf("expected collector_silent for eslogger, got %+v", p.CoverageItems)
	}
	if kinds["harness_uncovered"] == "" {
		t.Fatalf("expected harness_uncovered (agents active, zero hook events), got %+v", p.CoverageItems)
	}
	if p.NeedsYou != 0 {
		t.Fatalf("monitoring gaps are not decisions: %+v", p)
	}
	for _, it := range p.CoverageItems {
		if it.Kind == "collector_silent" && it.ID == "netsampler" {
			t.Fatal("netsampler silence is ambiguous — it must not be flagged")
		}
	}
}

// The root ES service crash-looping must surface even while the spool TAILER
// runs green: the tailer's heartbeat proves nothing about the writer.
func TestPostureFlagsCrashLoopingRootService(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture7_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	prev := collect.ESServiceProbe
	collect.ESServiceProbe = func() (collect.ESServiceSnapshot, error) {
		return collect.ESServiceSnapshot{State: "spawn scheduled (last exit 1)", SpoolMtime: time.Now().Add(-8 * 24 * time.Hour)}, nil
	}
	defer func() { collect.ESServiceProbe = prev }()
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status {
		return Status{
			Running: true, Uptime: "1h0m0s", ActiveAgents: 2,
			Collectors: []supervise.Health{{Name: "eslogger", Running: true, LastProduced: time.Now().UTC().Format(time.RFC3339)}},
			ESService:  &collect.ESServiceSnapshot{State: "spawn scheduled (last exit 1)", SpoolMtime: time.Now().Add(-8 * 24 * time.Hour)},
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("GET /posture: %v", err)
	}
	var p Posture
	decodeInto(t, resp, &p)
	found := false
	for _, it := range p.CoverageItems {
		if it.Kind == "collector_silent" && it.ID == "eslogger" && strings.Contains(it.Detail, "spawn scheduled") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected collector_silent for the crash-looping root service, got %+v", p.CoverageItems)
	}
}

// A failing root service AND a never-produced tailer are one blind spot:
// posture must carry exactly one collector_silent item for eslogger.
func TestPostureSingleESItemWhenProbeFails(t *testing.T) {
	st := Status{
		Running: true, Uptime: "1h0m0s", ActiveAgents: 2,
		Collectors: []supervise.Health{{Name: "eslogger", Running: true}}, // never produced
		ESService:  &collect.ESServiceSnapshot{State: "spawn scheduled (last exit 1)", SpoolMtime: time.Now().Add(-8 * 24 * time.Hour)},
	}
	count := 0
	for _, it := range silentCollectorItems(st) {
		if it.ID == "eslogger" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("eslogger items = %d, want exactly 1", count)
	}
	// Healthy probe + silent tailer: the tailer silence still surfaces.
	st.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now()}
	count = 0
	for _, it := range silentCollectorItems(st) {
		if it.ID == "eslogger" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("healthy probe + silent tailer: eslogger items = %d, want 1 (tailer silence)", count)
	}
}

// A running root service whose helper binary is newer than the last spool
// write lost its privacy grant: the item must name the re-grant. An older
// helper keeps the generic not-writing detail.
func TestESServiceItemsNamesRegrantAfterHelperReplaced(t *testing.T) {
	now := time.Now()
	replaced := esServiceItems(collect.ESServiceSnapshot{
		State: "running", SpoolSize: 10, SpoolMtime: now.Add(-2 * time.Hour), HelperMtime: now.Add(-time.Hour),
	})
	if len(replaced) != 1 || replaced[0].Kind != "collector_silent" {
		t.Fatalf("replaced helper: items = %+v, want one collector_silent", replaced)
	}
	d := replaced[0].Detail
	if !strings.Contains(d, "helper binary was replaced after the last write") ||
		!strings.Contains(d, "grant Full Disk Access again for Secure Agent") {
		t.Fatalf("replaced helper detail must name the re-grant, got %q", d)
	}
	if strings.Contains(d, collect.ESServiceLabel) {
		t.Fatalf("user-facing detail must name the app, not the launchd label: %q", d)
	}

	unchanged := esServiceItems(collect.ESServiceSnapshot{
		State: "running", SpoolSize: 10, SpoolMtime: now.Add(-2 * time.Hour), HelperMtime: now.Add(-3 * time.Hour),
	})
	if len(unchanged) != 1 {
		t.Fatalf("unchanged helper: items = %+v, want one", unchanged)
	}
	if strings.Contains(unchanged[0].Detail, "replaced") || !strings.Contains(unchanged[0].Detail, "file telemetry may be blind") {
		t.Fatalf("unchanged helper must keep the generic detail, got %q", unchanged[0].Detail)
	}

	// launchd keeps an earlier exit code after a restart: still running.
	restarted := esServiceItems(collect.ESServiceSnapshot{
		State: "running (last exit 1)", SpoolSize: 10, SpoolMtime: now.Add(-2 * time.Hour), HelperMtime: now.Add(-time.Hour),
	})
	if len(restarted) != 1 || !strings.Contains(restarted[0].Detail, "helper binary was replaced after the last write") {
		t.Fatalf("restarted helper: items = %+v, want the re-grant item, not a failing service", restarted)
	}
	if fresh := esServiceItems(collect.ESServiceSnapshot{State: "running (last exit 1)", SpoolSize: 10, SpoolMtime: now}); len(fresh) != 0 {
		t.Fatalf("restarted helper writing now: items = %+v, want none", fresh)
	}
}

// launchd refusing every spawn (78: EX_CONFIG, e.g. a registration bound to
// a replaced build) or a spawn-scheduled service that last exited nonzero
// needs Re-register; the posture detail names it.
func TestESServiceRefusedNamesReregister(t *testing.T) {
	for state, want := range map[string]bool{
		"spawn scheduled (last exit 78: EX_CONFIG)": true,
		"not running (last exit 78: EX_CONFIG)":     true,
		"spawn scheduled (last exit 1)":             true,
		"spawn scheduled":                           false,
		"not running (last exit 1)":                 false,
		"running (last exit 78: EX_CONFIG)":         false,
		"not-loaded":                                false,
	} {
		if got := esServiceRefused(state); got != want {
			t.Errorf("esServiceRefused(%q) = %v, want %v", state, got, want)
		}
	}

	stale := time.Now().Add(-8 * time.Minute)
	items := esServiceItems(collect.ESServiceSnapshot{State: "spawn scheduled (last exit 78: EX_CONFIG)", SpoolSize: 10, SpoolMtime: stale})
	if len(items) != 1 || !strings.Contains(items[0].Detail, "78: EX_CONFIG") || !strings.Contains(items[0].Detail, "Re-register") ||
		!strings.Contains(items[0].Detail, "/var/log/secure-agent-esd.log") {
		t.Fatalf("refused service: items = %+v, want one failing item naming the exit code, Re-register and the log", items)
	}
	plain := esServiceItems(collect.ESServiceSnapshot{State: "spawn scheduled", SpoolSize: 10, SpoolMtime: stale})
	if len(plain) != 1 || strings.Contains(plain[0].Detail, "Re-register") {
		t.Fatalf("spawn scheduled without an exit: items = %+v, want one failing item without Re-register", plain)
	}
}

// A writer producing mostly-unparseable lines (UnparsedShare over half) is
// real garbage and supersedes the ordinary not-writing/crash-loop items.
// Flooding (the tailer skipping past its per-tick budget) alone is a burst,
// not garbage: a short one is invisible, a sustained one reads as "falling
// behind", never as "flooding".
// timeAt returns a pointer to t, for optional time fields.
func timeAt(t time.Time) *time.Time { return &t }

func TestESServiceItemsFlooding(t *testing.T) {
	shortBurst := esServiceItems(collect.ESServiceSnapshot{
		State: "running", SpoolMtime: time.Now(), Flooding: true, UnparsedShare: 0, FloodingSince: timeAt(time.Now().Add(-5 * time.Second)),
	})
	if len(shortBurst) != 0 {
		t.Fatalf("Flooding=true, FloodingSince=5s ago: items = %+v, want none — a short burst is normal load", shortBurst)
	}
	sustained := esServiceItems(collect.ESServiceSnapshot{
		State: "running", SpoolMtime: time.Now(), Flooding: true, UnparsedShare: 0, FloodingSince: timeAt(time.Now().Add(-2 * time.Minute)),
	})
	if len(sustained) != 1 || sustained[0].Title != "File monitoring is falling behind" {
		t.Fatalf("Flooding=true, FloodingSince=2m ago: items = %+v, want one falling-behind item", sustained)
	}
	unparsed := esServiceItems(collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), UnparsedShare: 0.9})
	if len(unparsed) != 1 || unparsed[0].Title != "File monitoring writer is flooding" {
		t.Fatalf("UnparsedShare=0.9: items = %+v, want one flooding item", unparsed)
	}
	ok := esServiceItems(collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), UnparsedShare: 0.1})
	if len(ok) != 0 {
		t.Fatalf("UnparsedShare=0.1: items = %+v, want none", ok)
	}
}

// File events stored with their event time but delivered hours later read as
// a late monitor, not a healthy one; a stale spool's last lag does not.
func TestESServiceItemsLagging(t *testing.T) {
	late := esServiceItems(collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), NewestEventAt: timeAt(time.Now().Add(-2 * time.Hour)), LagSeconds: 7200})
	if len(late) != 1 || late[0].Title != "File monitoring is running late" || late[0].Severity != 2 || !strings.Contains(late[0].Detail, "2h0m0s before it arrived") {
		t.Fatalf("lag 2h: items = %+v, want one running-late item", late)
	}
	onTime := esServiceItems(collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), NewestEventAt: timeAt(time.Now()), LagSeconds: 119})
	if len(onTime) != 0 {
		t.Fatalf("lag 119s: items = %+v, want none", onTime)
	}
	idle := esServiceItems(collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now().Add(-10 * time.Minute), NewestEventAt: timeAt(time.Now().Add(-2 * time.Hour)), LagSeconds: 7200})
	if len(idle) != 0 {
		t.Fatalf("spool idle 10 min: items = %+v, want none", idle)
	}
}

// Garbage left in a spool nobody writes is not a flood: once the writer
// stops, the verdict yields to the service's real state.
func TestESServiceItemsStaleFloodYieldsToServiceState(t *testing.T) {
	idle := time.Now().Add(-10 * time.Minute)
	off := esServiceItems(collect.ESServiceSnapshot{State: "not-loaded", SpoolMtime: idle, Flooding: true, UnparsedShare: 0.99})
	if len(off) != 1 || off[0].Title != "File monitoring is off" || !strings.Contains(off[0].Detail, "Full Disk Access") {
		t.Fatalf("not-loaded after a flood: items = %+v, want one File monitoring is off item", off)
	}
	quiet := esServiceItems(collect.ESServiceSnapshot{State: "running", SpoolMtime: idle, Flooding: true, UnparsedShare: 0.99})
	if len(quiet) != 0 {
		t.Fatalf("running, spool idle 10 min, stale flood stats: items = %+v, want none", quiet)
	}
}

// No agents running: an idle machine is not a blind monitor — silence is
// legitimate, posture stays all-clear.
func TestPostureNoSilenceFlagsWhenIdle(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture6_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status {
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
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("GET /posture: %v", err)
	}
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
	a := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/posture")
	if err != nil {
		t.Fatalf("GET /posture: %v", err)
	}
	var p Posture
	decodeInto(t, resp, &p)
	if p.NeedsYou != 0 {
		t.Fatalf("48h-old flag counted: %+v", p)
	}
}

// decodeInto is a tiny helper so tests stay flat.
func decodeInto(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	if resp == nil {
		t.Fatal("decode: no response")
	}
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
	// Hermetic HOME: the item reads the live ~/.claude/settings.json; a
	// machine with the hook registered must not flip this test's outcome.
	t.Setenv("HOME", t.TempDir())
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

func TestHumanFlagTitleSecretInTranscript(t *testing.T) {
	if got := humanFlagTitle("secret-in-transcript"); got != "Secret appeared in an agent transcript" {
		t.Fatalf("humanFlagTitle(secret-in-transcript) = %q", got)
	}
}

// A severity-3 flag the advisor judged benign with high confidence is a
// queue item, not an emergency: posture reads "attention", never "critical".
func TestPostureBenignLikelyFlagIsAttention(t *testing.T) {
	put := func(withAdvisor bool) Posture {
		st := testStore(t)
		st.PutFlag(model.Flag{ID: "fp", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), Agent: "claude",
			Evidence: []model.EvidenceItem{{Kind: "read", Label: "/Users/x/.claude/skills/s/config", Sub: "sensitive read"}}})
		if withAdvisor {
			st.PutAdvisorVerdict("fp", "flag", model.AdvisorVerdict{Assessment: "benign", Confidence: 0.93, Rationale: "Own skill config.", SuggestedAction: "allow-host", CreatedAt: time.Now()})
		}
		return newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} }).computePosture()
	}
	p := put(true)
	if p.State != "attention" || len(p.Items) != 1 || p.Items[0].Severity != 1 {
		t.Fatalf("benign-likely posture = %+v, want attention with one severity-1 item", p)
	}
	if strings.HasSuffix(p.Summary, "act now.") {
		t.Fatalf("summary %q must not demand action for a likely-benign flag", p.Summary)
	}
	if !strings.HasPrefix(p.Items[0].Detail, "Likely benign (advisor 93 %) — ") {
		t.Fatalf("detail = %q, want the disposition first", p.Items[0].Detail)
	}
	if q := put(false); q.State != "critical" || q.Items[0].Severity != 3 || !strings.HasPrefix(q.Items[0].Detail, "Act now — ") {
		t.Fatalf("no-advisor posture = %+v, want critical", q)
	}
}
