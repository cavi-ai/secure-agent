package agents

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type fakeProcs map[int32]ProcInfo

func (f fakeProcs) List() []ProcInfo {
	res := make([]ProcInfo, 0, len(f))
	for _, p := range f {
		res = append(res, p)
	}
	return res
}

func (f fakeProcs) Info(pid int32) (ProcInfo, bool) {
	p, ok := f[pid]
	return p, ok
}

func TestTagInheritsFromAgentParent(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude"},
		200: {PID: 200, PPID: 100, Exe: "/usr/local/bin/node"},
		999: {PID: 999, PPID: 1, Exe: "/bin/ls"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	info, ok := tg.Tag(200)
	if !ok || info.Name != "claude" {
		t.Fatalf("Tag(200) = %+v, %v; want claude,true", info, ok)
	}
	if info.Kind != "agent" {
		t.Fatalf("Tag(200).Kind = %q, want agent", info.Kind)
	}
	if _, ok := tg.Tag(999); ok {
		t.Fatal("Tag(999) tagged an unrelated process")
	}
	if !tg.Any() {
		t.Fatal("Any() = false with a live agent")
	}
}

func TestParentPID(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/codex"},
		200: {PID: 200, PPID: 100, Exe: "/usr/local/bin/codex"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	if ppid, ok := tg.ParentPID(200); !ok || ppid != 100 {
		t.Fatalf("ParentPID(200) = %d, %v; want 100, true", ppid, ok)
	}
	if ppid, ok := tg.ParentPID(999); ok || ppid != 0 {
		t.Fatalf("ParentPID(999) = %d, %v; want 0, false", ppid, ok)
	}
	// A pid spawned after the last refresh is read from the process source.
	fake[300] = ProcInfo{PID: 300, PPID: 200, Exe: "/bin/zsh"}
	if ppid, ok := tg.ParentPID(300); !ok || ppid != 200 {
		t.Fatalf("ParentPID(300) = %d, %v; want 200, true", ppid, ok)
	}
}

// The Cursor IDE and local model servers are shared infrastructure, not
// agents: still tagged (monitored, killable) but marked kind=infra so counts
// and the "reclaimable" headline exclude them.
func TestTagMarksIDEAndModelServersAsInfra(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/Applications/Cursor.app/Contents/MacOS/Cursor"},
		101: {PID: 101, PPID: 1, Exe: "/usr/local/bin/ollama serve"},
		102: {PID: 102, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()

	ide, ok := tg.Tag(100)
	if !ok || ide.Name != "cursor-ide" || ide.Kind != config.AgentKindInfra {
		t.Fatalf("Tag(100) = %+v, %v; want cursor-ide/infra", ide, ok)
	}
	ollama, ok := tg.Tag(101)
	if !ok || ollama.Name != "ollama" || ollama.Kind != config.AgentKindInfra {
		t.Fatalf("Tag(101) = %+v, %v; want ollama/infra", ollama, ok)
	}
	// The cursor CLI harness stays an agent — only the IDE is infra.
	cli, ok := tg.Tag(102)
	if !ok || cli.Name != "cursor" || cli.Kind != "agent" {
		t.Fatalf("Tag(102) = %+v, %v; want cursor/agent", cli, ok)
	}
}

// OpenClaw runs its bundled node from under ~/.openclaw; the path segment,
// not the node basename, is what identifies the harness.
func TestTagOpenClawAsAgent(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/Volumes/x/.openclaw/node-v24/bin/node"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	info, ok := tg.Tag(100)
	if !ok || info.Name != "openclaw" || info.Kind != "agent" {
		t.Fatalf("Tag(100) = %+v, %v; want openclaw/agent", info, ok)
	}
}

type countingProcSource struct {
	procs     map[int32]ProcInfo
	infoCalls int
}

func (c *countingProcSource) List() []ProcInfo {
	res := make([]ProcInfo, 0, len(c.procs))
	for _, p := range c.procs {
		res = append(res, p)
	}
	return res
}

func (c *countingProcSource) Info(pid int32) (ProcInfo, bool) {
	c.infoCalls++
	p, ok := c.procs[pid]
	return p, ok
}

func TestRefreshZeroSyscallsOnIdleMachine(t *testing.T) {
	src := &countingProcSource{
		procs: map[int32]ProcInfo{
			1:  {PID: 1, PPID: 0, Comm: "launchd"},
			10: {PID: 10, PPID: 1, Comm: "WindowServer"},
			20: {PID: 20, PPID: 1, Comm: "Finder"},
			30: {PID: 30, PPID: 1, Comm: "zsh"},
			40: {PID: 40, PPID: 30, Comm: "ls"},
		},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, src)

	tg.Refresh()

	if src.infoCalls != 0 {
		t.Fatalf("Refresh executed %d Info syscalls on idle machine with no agents, expected 0", src.infoCalls)
	}
	if tg.Any() {
		t.Fatal("Any() returned true on idle machine")
	}

	// Now add an agent candidate
	src.procs[100] = ProcInfo{PID: 100, PPID: 1, Comm: "Cursor Helper"}
	src.procs[101] = ProcInfo{PID: 101, PPID: 100, Comm: "node"}

	tg.Refresh()
	if !tg.Any() {
		t.Fatal("Any() returned false after agent candidate spawned")
	}
}

func TestTaggedPIDsRootAndOrphan(t *testing.T) {
	start := time.Date(2026, 9, 9, 16, 0, 0, 0, time.UTC)
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: start, RSSBytes: 1000},
		200: {PID: 200, PPID: 100, Exe: "/usr/local/bin/node", StartTime: start.Add(time.Minute), RSSBytes: 200},
		300: {PID: 300, PPID: 999, Exe: "/usr/local/bin/claude", StartTime: start.Add(2 * time.Minute), RSSBytes: 50},
		400: {PID: 400, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: start.Add(3 * time.Minute), RSSBytes: 80},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()

	tagged := tg.TaggedPIDs()
	if tagged[100].RootPID != 100 {
		t.Fatalf("pid 100 root=%d, want 100", tagged[100].RootPID)
	}
	if tagged[200].RootPID != 100 {
		t.Fatalf("pid 200 root=%d, want 100 (inherited)", tagged[200].RootPID)
	}
	if tagged[400].RootPID != 400 {
		t.Fatalf("pid 400 root=%d, want 400 (second session)", tagged[400].RootPID)
	}
	if tagged[100].IsOrphan || tagged[200].IsOrphan || tagged[400].IsOrphan {
		t.Fatalf("live tree marked orphan: %+v", tagged)
	}
	if !tagged[300].IsOrphan {
		t.Fatal("pid 300 (parent 999 missing) should be orphan")
	}
	if tagged[300].RootPID != 300 {
		t.Fatalf("orphan root=%d, want 300", tagged[300].RootPID)
	}
}

// Tag reports the family root: the highest ancestor matching the same agent
// definition, and it agrees with TaggedPIDs.
func TestTagReportsFamilyRoot(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/opt/homebrew/bin/codex"},
		101: {PID: 101, PPID: 100, Exe: "/bin/zsh"},
		200: {PID: 200, PPID: 1, Exe: "/opt/homebrew/bin/codex"},
		201: {PID: 201, PPID: 200, Exe: "/opt/homebrew/lib/codex/bin/codex"},
		202: {PID: 202, PPID: 201, Exe: "/bin/zsh"},
		300: {PID: 300, PPID: 1, Exe: "/usr/local/bin/claude"},
		301: {PID: 301, PPID: 300, Exe: "/opt/homebrew/bin/codex"},
		302: {PID: 302, PPID: 301, Exe: "/bin/sh"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	// A pid spawned after the refresh is tagged through the process source.
	fake[203] = ProcInfo{PID: 203, PPID: 202, Exe: "/bin/zsh"}

	want := map[int32]int32{100: 100, 101: 100, 200: 200, 201: 200, 202: 200, 203: 200, 301: 301, 302: 301}
	for pid, root := range want {
		info, ok := tg.Tag(pid)
		if !ok || info.RootPID != root {
			t.Fatalf("Tag(%d) = root %d, %v; want %d", pid, info.RootPID, ok, root)
		}
	}
	tagged := tg.TaggedPIDs()
	for _, pid := range []int32{101, 202, 203, 302} {
		info, _ := tg.Tag(pid)
		if tagged[pid].RootPID != info.RootPID {
			t.Fatalf("pid %d: TaggedPIDs root %d, Tag root %d", pid, tagged[pid].RootPID, info.RootPID)
		}
	}
}

// Tag and TaggedPIDs must agree on the family root even when a shell
// between two codex processes is cached with Name "codex" through its
// ancestry rather than by matching the agent definition itself.
func TestFamilyRootAgreesAcrossCachedShell(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/opt/homebrew/bin/codex"},
		101: {PID: 101, PPID: 100, Exe: "/bin/zsh"},
		102: {PID: 102, PPID: 101, Exe: "/opt/homebrew/bin/codex"},
	}
	c, _ := config.Load("/nonexistent")

	// Outer, then the shell (which caches as "codex" via ancestry, not its
	// own exe), then the inner codex: familyRootLocked must recognize 101 as
	// same-family through the cache, not just through matchLocked.
	tg := New(c, fake)
	if _, ok := tg.Tag(100); !ok {
		t.Fatal("Tag(100) failed")
	}
	shell, ok := tg.Tag(101)
	if !ok || shell.Name != "codex" {
		t.Fatalf("Tag(101) = %+v, %v; want codex,true", shell, ok)
	}
	inner, ok := tg.Tag(102)
	if !ok || inner.RootPID != 100 {
		t.Fatalf("Tag(102).RootPID = %d, %v; want 100, true", inner.RootPID, ok)
	}
	if got := tg.TaggedPIDs()[102].RootPID; got != 100 {
		t.Fatalf("TaggedPIDs()[102].RootPID = %d, want 100", got)
	}

	// Reverse order: the inner codex is tagged first, so at that moment the
	// shell (101) is neither cached nor a def match. The walk must still
	// pass through it transparently to reach the def-matched outer codex.
	tg2 := New(c, fake)
	inner2, ok := tg2.Tag(102)
	if !ok || inner2.RootPID != 100 {
		t.Fatalf("Tag(102).RootPID (reverse order) = %d, %v; want 100, true", inner2.RootPID, ok)
	}
}

func TestFamilyRootStopsAtDifferentHarness(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/opt/homebrew/bin/codex"},
		101: {PID: 101, PPID: 100, Exe: "/bin/zsh"},
		102: {PID: 102, PPID: 101, Exe: "/usr/local/bin/claude"},
		103: {PID: 103, PPID: 102, Exe: "/bin/zsh"},
		104: {PID: 104, PPID: 103, Exe: "/opt/homebrew/bin/codex"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)

	// A claude ancestor (102) sits between the inner codex (104) and the
	// outer codex (100). The walk must stop at 102 (a different agent
	// definition), not pass through it to reach 100.
	inner, ok := tg.Tag(104)
	if !ok || inner.RootPID != 104 {
		t.Fatalf("Tag(104).RootPID = %d, %v; want 104, true", inner.RootPID, ok)
	}

	// Cache the intervening shells so the boundary is also hit through the
	// cached+tagged branch: 101 caches as "codex" (via ancestry to 100), 103
	// caches as "claude" (via ancestry to 102).
	if shell1, ok := tg.Tag(101); !ok || shell1.Name != "codex" {
		t.Fatalf("Tag(101) = %+v, %v; want codex,true", shell1, ok)
	}
	if shell2, ok := tg.Tag(103); !ok || shell2.Name != "claude" {
		t.Fatalf("Tag(103) = %+v, %v; want claude,true", shell2, ok)
	}

	if got := tg.TaggedPIDs()[104].RootPID; got != 104 {
		t.Fatalf("TaggedPIDs()[104].RootPID = %d, want 104", got)
	}
	outer, ok := tg.Tag(100)
	if !ok || outer.RootPID != 100 {
		t.Fatalf("Tag(100).RootPID = %d, %v; want 100, true", outer.RootPID, ok)
	}
}

func TestAlive(t *testing.T) {
	fake := fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude"}}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	// 200 is absent from the last process table but known to the source.
	fake[200] = ProcInfo{PID: 200, PPID: 1, Exe: "/usr/local/bin/claude"}
	if !tg.Alive(100) || !tg.Alive(200) {
		t.Fatalf("Alive(100)=%v Alive(200)=%v, want true, true", tg.Alive(100), tg.Alive(200))
	}
	if tg.Alive(300) {
		t.Fatal("Alive(300) = true for a pid unknown to table and source")
	}
	if _, cached := tg.TaggedPIDs()[200]; cached {
		t.Fatal("Alive tagged pid 200")
	}
}

func TestRefreshIntervalIdleVsBusy(t *testing.T) {
	if RefreshInterval(false) != 5*time.Second {
		t.Fatalf("idle interval = %s, want 5s", RefreshInterval(false))
	}
	if RefreshInterval(true) != 3*time.Second {
		t.Fatalf("busy interval = %s, want 3s", RefreshInterval(true))
	}
}

func TestCPUPercent(t *testing.T) {
	previousAt := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got := cpuPercent(time.Second, previousAt, 2*time.Second, previousAt.Add(2*time.Second))
	if got != 50 {
		t.Fatalf("cpuPercent=%v want 50", got)
	}
	if got := cpuPercent(2*time.Second, previousAt, time.Second, previousAt.Add(time.Second)); got != 0 {
		t.Fatalf("counter regression=%v want 0", got)
	}
	if got := cpuPercent(time.Second, previousAt, 2*time.Second, previousAt); got != 0 {
		t.Fatalf("zero wall delta=%v want 0", got)
	}
}

func TestRefreshUpdatesDynamicResources(t *testing.T) {
	start := time.Date(2026, 9, 15, 11, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	src := &countingProcSource{procs: map[int32]ProcInfo{
		100: {PID: 100, PPID: 1, Comm: "claude", Exe: "/usr/local/bin/claude", StartTime: start, RSSBytes: 100, CPUTime: time.Second},
	}}
	c, _ := config.Load("/nonexistent")
	tg := New(c, src)
	tg.now = func() time.Time { return now }
	tg.Refresh()

	src.procs[100] = ProcInfo{PID: 100, PPID: 1, Comm: "claude", Exe: "/usr/local/bin/claude", StartTime: start, RSSBytes: 250, CPUTime: 3 * time.Second}
	now = now.Add(2 * time.Second)
	tg.Refresh()

	info := tg.TaggedPIDs()[100]
	if info.RSSBytes != 250 {
		t.Fatalf("RSSBytes=%d want 250", info.RSSBytes)
	}
	if info.CPUPercent != 100 {
		t.Fatalf("CPUPercent=%v want 100", info.CPUPercent)
	}
	if !info.StartedAt.Equal(start) {
		t.Fatalf("StartedAt=%v want %v", info.StartedAt, start)
	}
}

func TestRefreshDoesNotCarryResourcesAcrossPIDReuse(t *testing.T) {
	firstStart := time.Date(2026, 9, 15, 11, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	src := &countingProcSource{procs: map[int32]ProcInfo{
		100: {PID: 100, PPID: 1, Comm: "claude", Exe: "/usr/local/bin/claude", StartTime: firstStart, RSSBytes: 500, CPUTime: 10 * time.Second},
	}}
	c, _ := config.Load("/nonexistent")
	tg := New(c, src)
	tg.now = func() time.Time { return now }
	tg.Refresh()

	secondStart := firstStart.Add(time.Hour)
	src.procs[100] = ProcInfo{PID: 100, PPID: 1, Comm: "claude", Exe: "/usr/local/bin/claude", StartTime: secondStart, RSSBytes: 50, CPUTime: time.Second}
	now = now.Add(time.Second)
	tg.Refresh()

	info := tg.TaggedPIDs()[100]
	if !info.StartedAt.Equal(secondStart) {
		t.Fatalf("StartedAt=%v want replacement start %v", info.StartedAt, secondStart)
	}
	if info.RSSBytes != 50 || info.CPUTime != time.Second || info.CPUPercent != 0 {
		t.Fatalf("replacement inherited resources: %+v", info)
	}
}

// Hermes Agent: the hermes-agent launcher, or anything under the .hermes
// home, is the harness. React Native's hermes engine binaries are not.
func TestTagHermesAsAgent(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/Users/x/.hermes/hermes-agent/venv/bin/python3.11"},
		101: {PID: 101, PPID: 1, Exe: "/opt/hermes-agent/bin/hermes-agent"},
		102: {PID: 102, PPID: 1, Exe: "/Users/x/.hermes/bin/hermes"},
		200: {PID: 200, PPID: 1, Exe: "/usr/local/bin/hermesc"},
		201: {PID: 201, PPID: 1, Exe: "/x/node_modules/hermes-engine/bin/hermes"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	for _, pid := range []int32{100, 101, 102} {
		info, ok := tg.Tag(pid)
		if !ok || info.Name != "hermes" || info.Kind != "agent" {
			t.Fatalf("Tag(%d) = %+v, %v; want hermes/agent", pid, info, ok)
		}
	}
	for _, pid := range []int32{200, 201} {
		if info, ok := tg.Tag(pid); ok {
			t.Fatalf("Tag(%d) = %+v; a React Native hermes binary is not the Hermes agent", pid, info)
		}
	}
}

// MatchExe applies the agent match strings to a bare exe path, so a pid the
// tagger has not cached is still named by its binary.
func TestMatchExeNamesAgentBeforeTag(t *testing.T) {
	c, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := New(c, fakeProcs{})
	if name, ok := tg.MatchExe("/Users/x/.local/share/claude/versions/2.1.280"); !ok || name != "claude" {
		t.Fatalf("MatchExe(claude versions) = %q, %v; want claude, true", name, ok)
	}
	if name, ok := tg.MatchExe("/usr/local/bin/hermesc"); ok {
		t.Fatalf("MatchExe(hermesc) = %q, true; want no hit", name)
	}
	if _, ok := tg.MatchExe(""); ok {
		t.Fatal("MatchExe(\"\") hit; want no hit")
	}
}

func TestRefreshReportsNewlyTaggedPIDsOnce(t *testing.T) {
	fake := fakeProcs{
		1:   {PID: 1, PPID: 0, Comm: "launchd"},
		999: {PID: 999, PPID: 1, Exe: "/bin/ls"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	calls := map[int32]int{}
	tg.SetOnTagged(func(pid int32, info AgentInfo) {
		if info.PID != pid || info.Name != "claude" {
			t.Errorf("onTagged(%d, %+v): want claude for the same pid", pid, info)
		}
		calls[pid]++
	})

	tg.Refresh()
	if len(calls) != 0 {
		t.Fatalf("a Refresh that tags nothing reported %v", calls)
	}

	fake[100] = ProcInfo{PID: 100, PPID: 1, Exe: "/usr/local/bin/claude"}
	fake[200] = ProcInfo{PID: 200, PPID: 100, Exe: "/usr/local/bin/node"}
	tg.Refresh()
	tg.Refresh()
	tg.Refresh()
	if len(calls) != 2 || calls[100] != 1 || calls[200] != 1 {
		t.Fatalf("onTagged calls = %v, want pid 100 and 200 once each", calls)
	}
}

func TestOnTaggedRunsOutsideTheLock(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	var got AgentInfo
	tg.SetOnTagged(func(pid int32, _ AgentInfo) {
		got, _ = tg.Tag(pid) // deadlocks if the callback runs under t.mu
	})
	done := make(chan struct{})
	go func() {
		tg.Refresh()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Refresh deadlocked: onTagged ran under the tagger lock")
	}
	if got.Name != "claude" {
		t.Fatalf("Tag from the callback = %+v, want claude", got)
	}
}

func TestRefreshRetriesPreviouslyUntaggedPID(t *testing.T) {
	fake := fakeProcs{
		200: {PID: 200, PPID: 100, Exe: "/usr/local/bin/node"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	calls := map[int32]int{}
	tg.SetOnTagged(func(pid int32, _ AgentInfo) { calls[pid]++ })

	if info, ok := tg.Tag(200); ok {
		t.Fatalf("Tag(200) with its parent absent = %+v, want untagged", info)
	}

	fake[100] = ProcInfo{PID: 100, PPID: 1, Exe: "/usr/local/bin/claude"}
	tg.Refresh()
	tg.Refresh()
	info, ok := tg.Tag(200)
	if !ok || info.Name != "claude" {
		t.Fatalf("Tag(200) after the parent appeared = %+v, %v, want claude", info, ok)
	}
	if calls[200] != 1 {
		t.Fatalf("onTagged calls for 200 = %d, want 1", calls[200])
	}
}
