package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

type fakeProcSource struct{}

func (f fakeProcSource) List() []agents.ProcInfo {
	return []agents.ProcInfo{
		{PID: 500, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
	}
}

func (f fakeProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 500 {
		return agents.ProcInfo{PID: 500, PPID: 1, Exe: "/usr/local/bin/cursor-agent"}, true
	}
	return agents.ProcInfo{}, false
}

func TestGuardBrokerMS(t *testing.T) {
	cases := []struct {
		name string
		hook int
		want int
	}{
		{"default when unset", 0, 42000},
		{"default when negative", -5, 42000},
		{"3s shorter than hook", 45000, 42000},
		{"floored at 1s", 3000, 1000},
		{"tiny hook still floored", 100, 1000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := guardBrokerMS(c.hook); got != c.want {
				t.Fatalf("guardBrokerMS(%d) = %d, want %d", c.hook, got, c.want)
			}
		})
	}
}

func TestTranscriptTailTargets(t *testing.T) {
	base := transcriptTailTargets("/home/x", "")
	// claude, cursor (legacy logs + project transcripts), codex, agy brain,
	// and the hook activity log. opencode is polled (SQLite), not a tail target.
	wantSubs := []string{".claude", ".cursor/logs", ".cursor/projects", ".codex", "antigravity-cli/brain", "activity.jsonl"}
	if len(base) != 10 {
		t.Fatalf("expected 10 base targets, got %d: %v", len(base), base)
	}
	// Transcripts are discovered by shape: every target but the activity log
	// is a glob, so no default target is a directory walk.
	for _, tgt := range base {
		if !strings.ContainsAny(tgt, "*?[") && !strings.HasSuffix(tgt, "activity.jsonl") {
			t.Errorf("target %q is not a glob; a directory target is walked recursively", tgt)
		}
	}
	for _, sub := range wantSubs {
		found := false
		for _, tgt := range base {
			if strings.Contains(tgt, sub) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no tail target covers %q: %v", sub, base)
		}
	}
	withJSONL := transcriptTailTargets("/home/x", "/var/log/events.jsonl")
	if len(withJSONL) != 11 || withJSONL[10] != "/var/log/events.jsonl" {
		t.Fatalf("jsonl path not appended: %v", withJSONL)
	}
}

func TestBuildStatusFn(t *testing.T) {
	cfg, _ := config.Load("/nonexistent")
	source := &treeProcSource{cpu: time.Second}
	tagger := agents.New(cfg, source)
	tagger.Refresh()
	time.Sleep(time.Millisecond)
	source.cpu = 2 * time.Second
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg)
	reg := supervise.NewRegistry()

	fn := buildStatusFn(nil, tagger, cr, nil, reg, nil, time.Now().Add(-2*time.Second),
		func() advisor.HealthSnapshot { return advisor.HealthSnapshot{Enabled: true} }, false, false)
	s := fn()

	if !s.Running {
		t.Fatal("status should report running")
	}
	if !s.AdvisorEnabled {
		t.Fatal("status must carry the advisor opt-in state")
	}
	if s.AdvisorHealth == nil {
		t.Fatal("status must carry advisor health (the UIs render circuit state from it)")
	}
	if s.Version == "" {
		t.Fatal("status must carry the build version (console badge reads it)")
	}
	if s.Uptime == "" || s.Uptime == "0s" {
		t.Fatalf("uptime should reflect the start time, got %q", s.Uptime)
	}
	// Roots vs processes: pid 500 is the tree root, 501 its helper child —
	// one agent, two tracked processes. (266 processes ≠ 266 agents.)
	if s.ActiveAgents != 1 {
		t.Fatalf("ActiveAgents = %d, want 1 root", s.ActiveAgents)
	}
	if s.TrackedProcesses != 2 {
		t.Fatalf("TrackedProcesses = %d, want 2", s.TrackedProcesses)
	}
	var cpu float64
	for _, agent := range s.Agents {
		cpu += agent.CPUPercent
	}
	if cpu <= 0 {
		t.Fatalf("status CPU sum=%v want sampled CPU", cpu)
	}
	if s.ProxyEnabled || s.ProxyPort != 0 {
		t.Fatalf("nil proxy must report disabled/0, got %v/%d", s.ProxyEnabled, s.ProxyPort)
	}
	if s.FirewallStats != nil {
		t.Fatalf("nil engine must report nil stats, got %v", s.FirewallStats)
	}
	if s.FleetConfigured {
		t.Fatal("status with no webhooks must not claim fleet is configured")
	}
}

func TestFleetConfiguredRequiresURLAndSecret(t *testing.T) {
	if fleetConfigured(nil) {
		t.Fatal("empty webhooks are not configured")
	}
	if fleetConfigured([]config.WebhookConfig{{URL: "https://example", Secret: ""}}) {
		t.Fatal("url without secret is not configured")
	}
	if !fleetConfigured([]config.WebhookConfig{{URL: "https://example", Secret: "s"}}) {
		t.Fatal("url+secret webhook is configured")
	}
}

// treeProcSource is a one-tree process list: cursor root (500) + zsh helper
// child (501) — the shape that used to count as two "agents".
type treeProcSource struct {
	cpu   time.Duration
	start time.Time
}

func (s *treeProcSource) List() []agents.ProcInfo {
	return []agents.ProcInfo{
		{PID: 500, PPID: 1, Exe: "/usr/local/bin/cursor-agent", StartTime: s.start, CPUTime: s.cpu, RSSBytes: 100},
		{PID: 501, PPID: 500, Comm: "zsh", CPUTime: s.cpu, RSSBytes: 50},
	}
}

func (s *treeProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 500 {
		return agents.ProcInfo{PID: 500, PPID: 1, Exe: "/usr/local/bin/cursor-agent", StartTime: s.start, CPUTime: s.cpu, RSSBytes: 100}, true
	}
	if pid == 501 {
		return agents.ProcInfo{PID: 501, PPID: 500, Comm: "zsh", CPUTime: s.cpu, RSSBytes: 50}, true
	}
	return agents.ProcInfo{}, false
}

func TestListActiveAgentsPreservesFractionalStartTime(t *testing.T) {
	cfg, _ := config.Load("/nonexistent")
	started := time.Date(2026, 9, 15, 12, 0, 0, 123456789, time.UTC)
	tagger := agents.New(cfg, &treeProcSource{start: started})
	tagger.Refresh()
	var got string
	for _, agent := range listActiveAgents(tagger) {
		if agent.PID == 500 {
			got = agent.StartedAt
			break
		}
	}
	if got != started.Format(time.RFC3339Nano) {
		t.Fatalf("started_at=%q want %q", got, started.Format(time.RFC3339Nano))
	}
}

func TestObserveResourcesBuildsSessionSnapshot(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "resources.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, &treeProcSource{cpu: time.Second})
	tagger.Refresh()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	st.PutEvent(event.Event{PID: 500, TS: now, Kind: event.KindPluginAction})
	tracker := resource.NewTracker()

	observeResources(tracker, tagger, st, now)
	snapshot := tracker.Snapshot()
	if snapshot.SessionCount != 1 || snapshot.ProcessCount != 2 || snapshot.RSSBytes != 150 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if snapshot.Sessions[0].LastSeenAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("last_seen=%q want %q", snapshot.Sessions[0].LastSeenAt, now.Format(time.RFC3339Nano))
	}
}

// Infra families (IDEs, model servers) are tracked and resourced but never
// counted as agents or sessions, and never diagnosed "reclaimable" — the
// 17.4 GB Cursor-as-reclaimable bug from the 2026-09 audit.
func TestInfraFamiliesAreCountedSeparately(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "resources.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	procs := &mixedProcSource{procs: []agents.ProcInfo{
		{PID: 500, PPID: 1, Exe: "/usr/local/bin/cursor-agent", RSSBytes: 100},
		{PID: 600, PPID: 1, Exe: "/Applications/Cursor.app/Contents/MacOS/Cursor", RSSBytes: 5 << 30},
		{PID: 601, PPID: 600, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Renderer)", RSSBytes: 3 << 30},
	}}
	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, procs)
	tagger.Refresh()
	tracker := resource.NewTracker()
	observeResources(tracker, tagger, st, time.Now())

	snapshot := tracker.Snapshot()
	if snapshot.SessionCount != 1 {
		t.Fatalf("SessionCount = %d, want 1 (infra excluded)", snapshot.SessionCount)
	}
	if snapshot.InfraCount != 1 {
		t.Fatalf("InfraCount = %d, want 1", snapshot.InfraCount)
	}
	for _, s := range snapshot.Sessions {
		if s.Kind == "infra" && (len(s.Diagnoses) > 0 || s.EstimatedReclaimBytes > 0) {
			t.Fatalf("infra session %q must carry no diagnoses or reclaim estimate: %+v", s.Name, s.Diagnoses)
		}
	}

	fn := buildStatusFn(nil, tagger, correlate.New(tagger, sensitive.New(cfg), cfg), nil,
		supervise.NewRegistry(), st, time.Now(),
		func() advisor.HealthSnapshot { return advisor.HealthSnapshot{} }, false, false)
	status := fn()
	if status.ActiveAgents != 1 {
		t.Fatalf("ActiveAgents = %d, want 1 (IDE excluded)", status.ActiveAgents)
	}
	if status.InfraCount != 1 {
		t.Fatalf("InfraCount = %d, want 1", status.InfraCount)
	}
}

type mixedProcSource struct{ procs []agents.ProcInfo }

func (m *mixedProcSource) List() []agents.ProcInfo { return m.procs }
func (m *mixedProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	for _, p := range m.procs {
		if p.PID == pid {
			return p, true
		}
	}
	return agents.ProcInfo{}, false
}

func TestResourceEpisodeWriterPersistsOnlyTransitions(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "episodes.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	writer := newResourceEpisodeWriter(st)
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	snapshot := resource.Snapshot{ObservedAt: now, Sessions: []resource.Session{{
		Key: "500:1", RootPID: 500, RSSBytes: 5 << 30,
		Diagnoses: []resource.Diagnosis{{Code: "heavy-memory", Severity: "critical"}},
	}}}

	writer.Observe(snapshot)
	writer.Observe(snapshot)
	writer.Close()
	if got := st.RecentResourceEpisodes(10); len(got) != 1 || got[0].Session.Key != "500:1" {
		t.Fatalf("episodes=%+v", got)
	}
}

type flakyResourceEpisodeStore struct {
	mu       sync.Mutex
	failures int
	saved    []resource.Episode
}

func (s *flakyResourceEpisodeStore) PutResourceEpisode(episode resource.Episode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures > 0 {
		s.failures--
		return errors.New("temporary sqlite failure")
	}
	s.saved = append(s.saved, episode)
	return nil
}

func TestResourceEpisodeWriterRetriesCapturedEpisode(t *testing.T) {
	st := &flakyResourceEpisodeStore{failures: 1}
	writer := newResourceEpisodeWriter(st)
	snapshot := resource.Snapshot{ObservedAt: time.Now(), Sessions: []resource.Session{{
		Key: "500:1", RootPID: 500, RSSBytes: 5 << 30,
		Diagnoses: []resource.Diagnosis{{Code: "heavy-memory", Severity: "critical"}},
	}}}
	writer.Observe(snapshot)
	writer.Close()

	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.saved) != 1 || st.saved[0].Session.Key != "500:1" {
		t.Fatalf("saved=%+v", st.saved)
	}
}

// The extracted drain loop: bus events must be persisted, correlated, and the
// done channel must close once the bus closes (shutdown waits on it).
func TestStartDrainLoopPersistsAndCloses(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg)

	b := bus.New(64)
	res := session.NewResolver(st, tagger)
	done := startDrainLoop(b.Subscribe(), st, cr, fleet.NewPublisher(), res, nil, nil, nil, nil)

	now := time.Now()
	b.Publish(event.Event{Kind: event.KindPluginAction, TS: now, PID: 500, Path: "/Users/x/project/.env"})
	time.Sleep(50 * time.Millisecond)
	b.Publish(event.Event{Kind: event.KindConnOpen, TS: now.Add(100 * time.Millisecond), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443})

	b.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain loop did not finish after bus close")
	}

	flags := st.RecentFlags(10)
	if len(flags) != 1 || flags[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("expected the correlated flag persisted, got %v", flags)
	}
	incidents := st.RecentIncidents(10)
	if len(incidents) == 0 {
		t.Fatal("drain loop must turn the flag into an incident report")
	}
}

// The drain loop stores a flag's own event and an agent's sensitive file
// event as record rows; everything else is bulk.
func TestDrainLoopMarksRecordRows(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg)

	b := bus.New(64)
	res := session.NewResolver(st, tagger)
	done := startDrainLoop(b.Subscribe(), st, cr, fleet.NewPublisher(), res, nil, nil, nil, nil)

	now := time.Now()
	b.Publish(event.Event{Kind: event.KindFileOpen, TS: now, PID: 500, Path: "/Users/x/project/main.go"})
	b.Publish(event.Event{Kind: event.KindFileOpen, TS: now, PID: 500, Path: "/System/Library/Keychains/SystemTrustSettings.plist"})
	b.Publish(event.Event{Kind: event.KindFileOpen, TS: now, PID: 500, Path: "/Users/x/.ssh/id_rsa"})
	time.Sleep(50 * time.Millisecond)
	b.Publish(event.Event{Kind: event.KindConnOpen, TS: now.Add(100 * time.Millisecond), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443})
	b.Publish(event.Event{Kind: event.KindConnOpen, TS: now.Add(200 * time.Millisecond), PID: 500, RemoteHost: "other.example.com", RemotePort: 443})

	b.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain loop did not finish after bus close")
	}

	if flags := st.RecentFlags(10); len(flags) != 1 || flags[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("flags = %v, want the one read-then-connect", flags)
	}
	got := map[string][2]int{}
	for _, r := range st.RetentionReport() {
		got[r.Name] = [2]int{r.Rows, r.RecordRows}
	}
	if want := [2]int{3, 1}; got["file-open"] != want {
		t.Errorf("file-open rows/record = %v, want %v (the ssh key read only)", got["file-open"], want)
	}
	if want := [2]int{2, 1}; got["conn-open"] != want {
		t.Errorf("conn-open rows/record = %v, want %v (the flagged connect only)", got["conn-open"], want)
	}
}

// File activity from a process outside every agent family is not stored
// unless it raised a flag; agent file activity and non-file kinds are.
func TestDrainLoopDropsUnattributedFileEvents(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg)

	b := bus.New(64)
	res := session.NewResolver(st, tagger)
	done := startDrainLoop(b.Subscribe(), st, cr, fleet.NewPublisher(), res, nil, nil, nil, nil)

	now := time.Now()
	b.Publish(event.Event{Kind: event.KindFileOpen, TS: now, PID: 500, Path: "/Users/x/project/main.go"})
	b.Publish(event.Event{Kind: event.KindFileOpen, TS: now, PID: 777, ExePath: "/System/Library/mds", Path: "/Users/x/notes.txt"})
	b.Publish(event.Event{Kind: event.KindFileWrite, TS: now, PID: 777, ExePath: "/System/Library/mds", Path: "/Users/x/notes.txt"})
	b.Publish(event.Event{Kind: event.KindFileDelete, TS: now, PID: 777, ExePath: "/System/Library/mds", Path: "/Users/x/notes.txt"})
	b.Publish(event.Event{Kind: event.KindExec, TS: now, PID: 777, ExePath: "/bin/ls", Path: "/bin/ls"})
	b.Publish(event.Event{Kind: event.KindFileOpen, TS: now, PID: 778, ExePath: "/Volumes/x/.openclaw/node-v24/bin/node",
		Path: "/Users/x/Library/Keychains/login.keychain-db"})

	b.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain loop did not finish after bus close")
	}

	got := map[string]bool{}
	for _, e := range st.RecentEvents(100) {
		got[fmt.Sprintf("%d/%s/%v", e.PID, e.Kind, e.SessionID != "")] = true
	}
	want := map[string]bool{
		fmt.Sprintf("500/%s/true", event.KindFileOpen):  true,
		fmt.Sprintf("777/%s/false", event.KindExec):     true,
		fmt.Sprintf("778/%s/false", event.KindFileOpen): true,
	}
	if len(got) != len(want) {
		t.Fatalf("stored events = %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("stored events = %v, missing %s", got, k)
		}
	}
	flags := st.RecentFlags(10)
	if len(flags) != 1 || flags[0].Rule != "keychain-access" {
		t.Fatalf("flags = %+v, want the one keychain-access flag", flags)
	}
}

func TestWatchParentExit(t *testing.T) {
	if ch := watchParentExit(1); ch != nil {
		t.Fatal("pid-1 launch must not start an orphan watch")
	}
}

func TestBuildNodeStatus(t *testing.T) {
	st := statusStub()
	p := postureStub("critical", "Secret leaving in agent traffic — act now.", 2)
	labels := map[string]string{"env": "prod", "role": "build-runner"}
	ns := buildNodeStatus(st, p, "builder-01", labels, resource.BudgetSummary{Mode: "prompt", Enforced: true, OverBudget: 1})
	if ns.Hostname != "builder-01" || ns.PostureState != "critical" || ns.NeedsYou != 2 {
		t.Fatalf("node status = %+v", ns)
	}
	if ns.PostureSummary != p.Summary || ns.Agents != st.ActiveAgents || ns.Uptime != st.Uptime {
		t.Fatalf("payload must mirror status+posture: %+v", ns)
	}
	if ns.Labels["env"] != "prod" || ns.OS == "" || ns.Arch == "" {
		t.Fatalf("labels/os/arch missing: %+v", ns)
	}
	if ns.Budget == nil || ns.Budget.Mode != "prompt" || !ns.Budget.Enforced || ns.Budget.OverBudget != 1 {
		t.Fatalf("budget posture not carried in the heartbeat: %+v", ns.Budget)
	}
}

func statusStub() api.Status {
	return api.Status{Running: true, Version: "v9", Uptime: "1h0m0s", ActiveAgents: 3}
}

func postureStub(state, summary string, needsYou int) api.Posture {
	return api.Posture{State: state, Summary: summary, NeedsYou: needsYou, Items: []api.PostureItem{}}
}

// The heartbeat loop must push once at boot, on the ticker, and IMMEDIATELY
// when the posture state flips — a node going critical cannot wait out a
// 60s interval.
func TestFleetHeartbeatLoopPushesOnTransition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	pushes := 0
	state := "all-clear"
	push := func() string {
		mu.Lock()
		defer mu.Unlock()
		pushes++
		return state
	}
	stateFn := func() string { mu.Lock(); defer mu.Unlock(); return state }

	// Heartbeat far in the future: only boot + transition pushes should fire.
	go fleetHeartbeatLoop(ctx, push, stateFn, func() time.Duration { return time.Hour }, 20*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	state = "critical"
	mu.Unlock()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if pushes != 2 {
		t.Fatalf("pushes = %d, want 2 (boot + transition)", pushes)
	}
}

func TestFleetHeartbeatLoopTicks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	pushes := 0
	push := func() string { mu.Lock(); defer mu.Unlock(); pushes++; return "all-clear" }
	stateFn := func() string { return "all-clear" }

	go fleetHeartbeatLoop(ctx, push, stateFn, func() time.Duration { return 30 * time.Millisecond }, time.Hour)
	time.Sleep(110 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if pushes < 3 { // boot + at least 2 ticks
		t.Fatalf("pushes = %d, want >= 3 (boot + ticks)", pushes)
	}
}

// Unfleeted nodes arm the loop but publish nothing — enrolling a collector
// at runtime (config hot-reload) must work without a daemon restart.
func TestStartFleetHeartbeatNoopWithoutSinks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := api.New(api.Deps{Store: st, Status: func() api.Status { return statusStub() }})
	cfgGet := func() config.FleetConfig { return config.FleetConfig{} }
	startFleetHeartbeat(ctx, srv, func() api.Status { return statusStub() }, fleet.NewPublisher(), cfgGet)
	startFleetHeartbeat(ctx, srv, func() api.Status { return statusStub() }, nil, cfgGet) // nil publisher: no loop at all
	time.Sleep(50 * time.Millisecond)
	// No panic, no delivery, nothing else to assert — the loop is inert.
}

// CODEX_HOME moves the rollout store; the tail targets must follow it while
// keeping the default path covered.
func TestTranscriptTailTargetsFollowCodexHome(t *testing.T) {
	home := "/Users/x"
	t.Setenv("CODEX_HOME", "/tmp/codex-alt")
	targets := transcriptTailTargets(home, "")
	foundDefault, foundAlt := false, false
	for _, p := range targets {
		if p == collect.CodexRolloutGlob(filepath.Join(home, ".codex")) {
			foundDefault = true
		}
		if p == "/tmp/codex-alt/sessions/*/*/*/rollout-*.jsonl" {
			foundAlt = true
		}
	}
	if !foundDefault || !foundAlt {
		t.Fatalf("targets = %v; want default + CODEX_HOME", targets)
	}
	// A CODEX_HOME equal to the default must not duplicate the target.
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	for _, p := range transcriptTailTargets(home, "") {
		if strings.HasPrefix(p, "/tmp/codex-alt/") {
			t.Fatal("stale CODEX_HOME target leaked")
		}
	}
}

// A launcher that relocates codex's home per process (orchestrated agents)
// must surface as a tail target via the process's own environment — the
// daemon's env never sees it.
func TestCodexSessionTargetsFromLiveProcesses(t *testing.T) {
	procs := map[int32]agents.AgentInfo{
		100: {Name: "codex"},
		101: {Name: "codex"},
		200: {Name: "claude"}, // other harness: ignored
		300: {Name: "codex"},  // no CODEX_HOME
	}
	env := map[int32]string{100: "/data/orch/agent-a/codex-home", 101: "/data/orch/agent-a/codex-home"}
	envOf := func(pid int32, key string) string {
		if key != "CODEX_HOME" {
			return ""
		}
		return env[pid]
	}
	got := codexSessionTargetsFrom(procs, envOf, "/Users/x")
	if len(got) != 1 || got[0] != "/data/orch/agent-a/codex-home/sessions/*/*/*/rollout-*.jsonl" {
		t.Fatalf("targets = %v, want the deduped per-process rollout glob", got)
	}
	// The default codex home is already covered by transcriptTailTargets.
	env[100] = "/Users/x/.codex"
	if got := codexSessionTargetsFrom(map[int32]agents.AgentInfo{100: {Name: "codex"}}, envOf, "/Users/x"); len(got) != 0 {
		t.Fatalf("default CODEX_HOME must not duplicate the built-in target: %v", got)
	}
}
