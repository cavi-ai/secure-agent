package agents

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

var (
	lineageStart = time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	// jobStart is the job's start as the process table reads it, at
	// microseconds; its fork record carries nanoseconds past that.
	jobStart = lineageStart.Add(3*time.Second + 123456*time.Microsecond)
)

func lineageConfig() config.Config {
	return config.Config{Agents: []config.AgentDef{{Name: "claude", Kind: "agent", Match: []string{"/claude"}}}}
}

// lineageProcs lists launchd, the agent (500) and the job (900) adopted by
// launchd; the shell (600) and subshell (700) between them have exited.
func lineageProcs() fakeProcs {
	return fakeProcs{
		1:   {PID: 1, Comm: "launchd", StartTime: lineageStart.Add(-time.Hour)},
		500: {PID: 500, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/Users/x/project", StartTime: lineageStart},
		900: {PID: 900, PPID: 1, Exe: "/bin/sleep", CWD: "/Users/x/project", StartTime: jobStart},
	}
}

func lineageAt(s int) time.Time { return lineageStart.Add(time.Duration(s) * time.Second) }

// forkChain is agent -> shell -> subshell -> job as fork records report it.
func forkChain() []Lineage {
	return []Lineage{
		{ParentPID: 500, ParentStart: lineageAt(0), ChildPID: 600, ChildStart: lineageAt(1), At: lineageAt(1)},
		{ParentPID: 600, ParentStart: lineageAt(1), ChildPID: 700, ChildStart: lineageAt(2), At: lineageAt(2)},
		{ParentPID: 700, ParentStart: lineageAt(2), ChildPID: 900, ChildStart: jobStart.Add(789 * time.Nanosecond), At: lineageAt(4)},
	}
}

func noteAll(tg *Tagger, ls []Lineage) {
	for _, l := range ls {
		tg.NoteLineage(l)
	}
}

func assertJobIsClaude(t *testing.T, tg *Tagger) {
	t.Helper()
	info, ok := tg.Tag(900)
	if !ok || info.Name != "claude" || info.Kind != "agent" || info.RootPID != 500 {
		t.Fatalf("Tag(job) = %+v, %v; want claude agent rooted at 500", info, ok)
	}
	if info.PID != 900 || info.PPID != 1 || info.ExePath != "/bin/sleep" || info.CWD != "/Users/x/project" || !info.StartedAt.Equal(jobStart) {
		t.Fatalf("Tag(job) details = %+v; want the job's own live details", info)
	}
	if agent, known := tg.LiveAgentFamily(900); !agent || !known {
		t.Fatalf("LiveAgentFamily(job) = (%v, %v), want (true, true)", agent, known)
	}
}

func TestLineageKeepsFamilyAfterAncestorsExit(t *testing.T) {
	tg := New(lineageConfig(), lineageProcs())
	tg.Refresh()
	noteAll(tg, forkChain())
	assertJobIsClaude(t, tg)
}

func TestLineageReplacesACachedMiss(t *testing.T) {
	tg := New(lineageConfig(), lineageProcs())
	tg.Refresh()
	if info, ok := tg.Tag(900); ok {
		t.Fatalf("Tag(job) before its lineage = %+v, want untagged", info)
	}
	noteAll(tg, forkChain())
	assertJobIsClaude(t, tg)
}

func TestLineageIsNotInheritedByARecycledPID(t *testing.T) {
	procs := lineageProcs()
	procs[900] = ProcInfo{PID: 900, PPID: 1, Exe: "/bin/cat", StartTime: lineageStart.Add(10 * time.Minute)}
	tg := New(lineageConfig(), procs)
	tg.Refresh()
	noteAll(tg, forkChain())
	if info, ok := tg.Tag(900); ok {
		t.Fatalf("Tag(recycled pid) = %+v, want untagged", info)
	}
	if agent, known := tg.LiveAgentFamily(900); agent || !known {
		t.Fatalf("LiveAgentFamily(recycled pid) = (%v, %v), want (false, true)", agent, known)
	}
}

func TestLineageOutsideEveryFamilyStoresNothing(t *testing.T) {
	src := &countingProcSource{procs: map[int32]ProcInfo{
		1:   {PID: 1, Comm: "launchd", StartTime: lineageStart.Add(-time.Hour)},
		400: {PID: 400, PPID: 1, Exe: "/bin/zsh", StartTime: lineageStart},
		950: {PID: 950, PPID: 1, Exe: "/bin/sleep", StartTime: lineageAt(3)},
	}}
	tg := New(lineageConfig(), src)
	tg.Refresh()
	reads := src.infoCalls
	noteAll(tg, []Lineage{
		{ParentPID: 400, ParentStart: lineageAt(0), ChildPID: 650, ChildStart: lineageAt(1), At: lineageAt(1)},
		{ParentPID: 650, ParentStart: lineageAt(1), ChildPID: 950, ChildStart: lineageAt(3), At: lineageAt(3)},
		{ParentPID: 650, ChildPID: 950, ChildStart: lineageAt(3), At: lineageAt(3)},
	})
	if src.infoCalls != reads || len(tg.lineage) != 0 {
		t.Fatalf("observations outside every family read the process source %d times and stored %d records",
			src.infoCalls-reads, len(tg.lineage))
	}
	if info, ok := tg.Tag(950); ok {
		t.Fatalf("Tag(child of a non-agent) = %+v, want untagged", info)
	}
	if agent, known := tg.LiveAgentFamily(950); agent || !known {
		t.Fatalf("LiveAgentFamily(child of a non-agent) = (%v, %v), want (false, true)", agent, known)
	}
}

// An exited shell's record names its children's family for
// lineageRetention after a refresh found it gone, and not after.
func TestLineageOfAnExitedParentExpires(t *testing.T) {
	for _, c := range []struct {
		after  time.Duration
		tagged bool
	}{{time.Minute, true}, {lineageRetention + time.Second, false}} {
		now := lineageAt(5)
		tg := New(lineageConfig(), lineageProcs())
		tg.now = func() time.Time { return now }
		tg.Refresh()
		chain := forkChain()
		tg.NoteLineage(chain[0])
		tg.Refresh() // the shell is not listed: its record is an exited one
		now = now.Add(c.after)
		noteAll(tg, chain[1:])
		if _, ok := tg.Tag(900); ok != c.tagged {
			t.Fatalf("%v after the shell exited: Tag(job) tagged = %v, want %v", c.after, ok, c.tagged)
		}
	}
}

// At the cap, exited records go first: the oldest record, a live job's,
// outlasts thousands of newer records of exited processes.
func TestLineageStaysWithinItsCap(t *testing.T) {
	tg := New(lineageConfig(), lineageProcs())
	tg.Refresh()
	note := func(child int32) {
		tg.NoteLineage(Lineage{ParentPID: 500, ParentStart: lineageStart, ChildPID: child, ChildStart: jobStart, At: lineageAt(4)})
		if n := len(tg.lineage); n > lineageCap {
			t.Fatalf("%d lineage records, cap %d", n, lineageCap)
		}
	}
	note(900)
	for pid := int32(10000); pid < 10000+lineageCap; pid++ {
		note(pid)
	}
	tg.Refresh()
	for pid := int32(30000); pid < 30200; pid++ {
		note(pid)
	}
	assertJobIsClaude(t, tg)
}

// A tag from a record is rooted at the process itself once another process
// holds the recorded root's pid.
func TestLineageRootMustStillBeTheRecordedProcess(t *testing.T) {
	procs := lineageProcs()
	tg := New(lineageConfig(), procs)
	tg.Refresh()
	noteAll(tg, forkChain())
	procs[500] = ProcInfo{PID: 500, PPID: 1, Exe: "/bin/cat", StartTime: lineageStart.Add(10 * time.Minute)}
	tg.Refresh()
	info, ok := tg.Tag(900)
	if !ok || info.Name != "claude" || info.RootPID != 900 || !slices.Equal(info.Chain, []int32{900}) {
		t.Fatalf("Tag(job) after its root's pid was reused = %+v, %v; want claude rooted at 900, chain [900]", info, ok)
	}
	if agent, known := tg.LiveAgentFamily(900); !agent || !known {
		t.Fatalf("LiveAgentFamily(job) = (%v, %v), want (true, true)", agent, known)
	}
}

// Exec records name the parent by pid alone; they carry the family when no
// fork record was read.
func TestLineageFromExecRecordsAlone(t *testing.T) {
	tg := New(lineageConfig(), lineageProcs())
	tg.Refresh()
	noteAll(tg, []Lineage{
		{ParentPID: 500, ChildPID: 600, ChildStart: lineageAt(1), At: lineageAt(1)},
		{ParentPID: 600, ChildPID: 900, ChildStart: jobStart, At: lineageAt(4)},
	})
	assertJobIsClaude(t, tg)
}

// A parent named by pid alone carries its family only into records made
// before a refresh found it gone.
func TestLineageExecParentMustBeAliveAtTheRecord(t *testing.T) {
	for _, c := range []struct {
		name   string
		at     time.Time
		tagged bool
	}{
		{"exec before the shell was found gone", lineageAt(4), true},
		{"exec after the shell was found gone", lineageAt(6), false},
	} {
		now := lineageAt(0)
		tg := New(lineageConfig(), lineageProcs())
		tg.now = func() time.Time { return now }
		tg.Refresh()
		tg.NoteLineage(Lineage{ParentPID: 500, ChildPID: 600, ChildStart: lineageAt(1), At: lineageAt(1)})
		now = lineageAt(5)
		tg.Refresh() // the shell is not listed: its record is marked exited at lineageAt(5)
		tg.NoteLineage(Lineage{ParentPID: 600, ChildPID: 900, ChildStart: jobStart, At: c.at})
		if info, ok := tg.Tag(900); ok != c.tagged || (ok && info.Name != "claude") {
			t.Fatalf("%s: Tag(job) = %+v, %v; want tagged %v as claude", c.name, info, ok, c.tagged)
		}
		if c.tagged {
			continue
		}
		if agent, known := tg.LiveAgentFamily(900); agent || !known {
			t.Fatalf("%s: LiveAgentFamily(job) = (%v, %v), want (false, true)", c.name, agent, known)
		}
	}
}

// A family removed from the definitions no longer tags through its records.
func TestLineageFollowsTheAgentDefinitions(t *testing.T) {
	tg := New(lineageConfig(), lineageProcs())
	tg.Refresh()
	noteAll(tg, forkChain())
	tg.SetAgents(nil)
	if info, ok := tg.Tag(900); ok {
		t.Fatalf("Tag(job) after its agent was removed = %+v, want untagged", info)
	}
}
