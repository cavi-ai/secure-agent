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
		100: {PID: 100, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"},
		200: {PID: 200, PPID: 100, Exe: "/usr/local/bin/node"},
		999: {PID: 999, PPID: 1, Exe: "/bin/ls"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	info, ok := tg.Tag(200)
	if !ok || info.Name != "cursor" {
		t.Fatalf("Tag(200) = %+v, %v; want cursor,true", info, ok)
	}
	if _, ok := tg.Tag(999); ok {
		t.Fatal("Tag(999) tagged an unrelated process")
	}
	if !tg.Any() {
		t.Fatal("Any() = false with a live agent")
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
