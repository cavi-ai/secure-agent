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

// capProcs is lineageProcs with two more listed processes, 950 and 960,
// whose fork records are read after the cap was reached.
func capProcs() fakeProcs {
	procs := lineageProcs()
	procs[950] = ProcInfo{PID: 950, PPID: 1, Exe: "/bin/sleep", StartTime: lineageAt(20)}
	procs[960] = ProcInfo{PID: 960, PPID: 1, Exe: "/bin/sleep", StartTime: lineageAt(20)}
	return procs
}

// noteJob notes the agent's fork record of the listed job, the oldest record.
func noteJob(tg *Tagger) {
	tg.NoteLineage(Lineage{ParentPID: 500, ParentStart: lineageStart, ChildPID: 900, ChildStart: jobStart, At: lineageAt(4)})
}

// noteFromAgent notes the agent's fork record of child, started at at, and
// checks the record count stays within the cap.
func noteFromAgent(t *testing.T, tg *Tagger, child int32, at time.Time) {
	t.Helper()
	tg.NoteLineage(Lineage{ParentPID: 500, ParentStart: lineageStart, ChildPID: child, ChildStart: at, At: at})
	if n := len(tg.lineage); n > lineageCap {
		t.Fatalf("%d lineage records after noting %d, cap %d", n, child, lineageCap)
	}
}

// assertParentCarries notes parent's fork record of the listed child and
// checks whether the child joined the agent's family through it.
func assertParentCarries(t *testing.T, tg *Tagger, parent int32, parentStart time.Time, child int32, want bool) {
	t.Helper()
	tg.NoteLineage(Lineage{ParentPID: parent, ParentStart: parentStart, ChildPID: child, ChildStart: lineageAt(20), At: lineageAt(21)})
	if info, ok := tg.Tag(child); ok != want || (ok && info.Name != "claude") {
		t.Fatalf("Tag(%d) through parent %d = %+v, %v; want tagged %v as claude", child, parent, info, ok, want)
	}
	if agent, known := tg.LiveAgentFamily(child); agent != want || !known {
		t.Fatalf("LiveAgentFamily(%d) through parent %d = (%v, %v), want (%v, true)", child, parent, agent, known, want)
	}
}

// At the cap, records the process table does not list go before the record
// of a listed process, however old it is.
func TestLineageCapDropsUnlistedBeforeListed(t *testing.T) {
	tg := New(lineageConfig(), lineageProcs())
	tg.Refresh()
	noteJob(tg)
	for pid := int32(10000); pid < 10000+lineageCap+200; pid++ {
		noteFromAgent(t, tg, pid, lineageAt(5))
	}
	assertJobIsClaude(t, tg)
}

// At the cap, records a refresh marked exited go before unlisted ones.
func TestLineageCapDropsExitedBeforeUnlisted(t *testing.T) {
	tg := New(lineageConfig(), capProcs())
	tg.Refresh()
	noteJob(tg)
	for i := range int32(4000) {
		noteFromAgent(t, tg, 10000+i, lineageAt(5).Add(time.Duration(i)))
	}
	tg.Refresh() // the first batch is not listed: its records are marked exited
	for i := range int32(5000) {
		noteFromAgent(t, tg, 20000+i, lineageAt(6).Add(time.Duration(i)))
	}
	assertJobIsClaude(t, tg)
	assertParentCarries(t, tg, 24999, lineageAt(6).Add(4999), 950, true)
	assertParentCarries(t, tg, 10000, lineageAt(5), 960, false)
}

// Among unlisted records, the oldest go first.
func TestLineageCapDropsOldestFirst(t *testing.T) {
	tg := New(lineageConfig(), capProcs())
	tg.Refresh()
	for i := range int32(lineageCap + 1) {
		noteFromAgent(t, tg, 10000+i, lineageAt(5).Add(time.Duration(i)*time.Microsecond))
	}
	assertParentCarries(t, tg, 10000+lineageCap, lineageAt(5).Add(lineageCap*time.Microsecond), 950, true)
	assertParentCarries(t, tg, 10000, lineageAt(5), 960, false)
}

// A tag from a record is rooted at the process itself once another process
// holds the recorded root's pid.
func TestLineageRootMustStillBeTheRecordedProcess(t *testing.T) {
	procs := lineageProcs()
	tg := New(lineageConfig(), procs)
	tg.Refresh()
	noteAll(tg, forkChain())
	assertJobIsClaude(t, tg)
	if got := tg.TaggedPIDs()[900].RootPID; got != 500 {
		t.Errorf("TaggedPIDs()[900].RootPID = %d before reuse, want 500", got)
	}
	procs[500] = ProcInfo{PID: 500, PPID: 1, Exe: "/bin/cat", StartTime: lineageStart.Add(10 * time.Minute)}
	tg.Refresh()
	info, ok := tg.Tag(900)
	if !ok || info.Name != "claude" || info.RootPID != 900 || !slices.Equal(info.Chain, []int32{900}) {
		t.Fatalf("Tag(job) after its root's pid was reused = %+v, %v; want claude rooted at 900, chain [900]", info, ok)
	}
	if agent, known := tg.LiveAgentFamily(900); !agent || !known {
		t.Fatalf("LiveAgentFamily(job) = (%v, %v), want (true, true)", agent, known)
	}
	if got := tg.TaggedPIDs()[900].RootPID; got != 900 {
		t.Fatalf("TaggedPIDs()[900].RootPID = %d after reuse, want 900", got)
	}
}

func TestLineageDescendantKeepsExitedRootIdentity(t *testing.T) {
	procs := lineageProcs()
	tg := New(lineageConfig(), procs)
	tg.Refresh()
	noteAll(tg, forkChain())
	assertJobIsClaude(t, tg)

	delete(procs, 500)
	tg.Refresh()
	procs[901] = ProcInfo{PID: 901, PPID: 1, Exe: "/bin/sleep", StartTime: lineageAt(6)}
	tg.NoteLineage(Lineage{ParentPID: 900, ParentStart: jobStart, ChildPID: 901, ChildStart: lineageAt(6), At: lineageAt(6)})
	if info, ok := tg.Tag(901); !ok || info.RootPID != 500 {
		t.Fatalf("Tag(descendant) with exited root = %+v, %v; want root 500", info, ok)
	}

	procs[500] = ProcInfo{PID: 500, PPID: 1, Exe: "/bin/cat", StartTime: lineageAt(7)}
	tg.Refresh()
	if info, ok := tg.Tag(901); !ok || info.RootPID != 901 {
		t.Fatalf("Tag(descendant) after root reuse = %+v, %v; want root 901", info, ok)
	}
	delete(procs, 500)
	tg.Refresh()
	if info, ok := tg.Tag(901); !ok || info.RootPID != 901 {
		t.Fatalf("Tag(descendant) after the replacement exits = %+v, %v; want root 901", info, ok)
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

func TestLineageAgentExecSeedsFamilyWithoutARefresh(t *testing.T) {
	procs := lineageProcs()
	delete(procs, 500)
	tg := New(lineageConfig(), procs)
	tg.NoteLineage(Lineage{ParentPID: 1, ChildPID: 500, ChildStart: lineageStart, ExecPath: "/usr/local/bin/claude", At: lineageStart})
	noteAll(tg, forkChain())
	assertJobIsClaude(t, tg)
}

func TestDetachedAuthorizationRecordsEndpointSecurityRoots(t *testing.T) {
	for _, tc := range []struct {
		name string
		note Lineage
	}{
		{"exec", Lineage{ParentPID: 1, ChildPID: 500, ChildStart: lineageStart, ExecPath: "/usr/local/bin/claude", At: lineageStart}},
		{"fork", Lineage{ParentPID: 500, ParentStart: lineageStart, ParentExe: "/usr/local/bin/claude", ChildPID: 600, ChildStart: lineageAt(1), At: lineageAt(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procs := lineageProcs()
			delete(procs, 500)
			job := procs[900]
			job.PGID = 700
			procs[900] = job
			tg := New(lineageConfig(), procs)
			tg.NoteLineage(tc.note)
			if agent, known := tg.LiveAgentFamily(900); agent || known {
				t.Errorf("detached job after an Endpoint Security root observation = (%v, %v), want (false, false)", agent, known)
			}
		})
	}
}

func TestLineageRootCanBeNewerThanTheLastSample(t *testing.T) {
	procs := lineageProcs()
	procs[500] = ProcInfo{PID: 500, PPID: 1, Exe: "/bin/cat", StartTime: lineageAt(-5)}
	tg := New(lineageConfig(), procs)
	tg.Refresh()
	procs[500] = lineageProcs()[500]
	tg.NoteLineage(Lineage{ParentPID: 1, ChildPID: 500, ChildStart: lineageStart, ExecPath: "/usr/local/bin/claude", At: lineageStart})
	noteAll(tg, forkChain())
	tg.Refresh()
	assertJobIsClaude(t, tg)
}

func TestLineageOriginalParentUsesChildBirth(t *testing.T) {
	for _, start := range []time.Time{jobStart, {}} {
		procs := lineageProcs()
		p := procs[500]
		p.StartTime = lineageAt(5)
		procs[500] = p
		tg := New(lineageConfig(), procs)
		tg.Refresh()
		tg.NoteLineage(Lineage{ParentPID: 500, ChildPID: 900, ChildStart: start, OriginalParent: true, At: lineageAt(6)})
		if info, ok := tg.Tag(900); ok {
			t.Fatalf("Tag(job) with child start %v = %+v, want untagged", start, info)
		}
	}
}

func TestLineageExecPreservesVerifiedFork(t *testing.T) {
	procs := lineageProcs()
	procs[510] = ProcInfo{PID: 510, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: lineageStart}
	tg := New(lineageConfig(), procs)
	tg.Refresh()
	noteAll(tg, forkChain())
	tg.NoteLineage(Lineage{ParentPID: 510, ChildPID: 900, ChildStart: jobStart, OriginalParent: true, At: lineageAt(6)})
	assertJobIsClaude(t, tg)
}

func TestLiveAgentFamilyRecognizesAdoptedAncestor(t *testing.T) {
	procs := lineageProcs()
	procs[901] = ProcInfo{PID: 901, PPID: 900, Exe: "/bin/sleep", StartTime: lineageAt(6)}
	tg := New(lineageConfig(), procs)
	tg.Refresh()
	noteAll(tg, forkChain())
	if agent, known := tg.LiveAgentFamily(901); !agent || !known {
		t.Fatalf("LiveAgentFamily(descendant) = (%v, %v), want (true, true)", agent, known)
	}
}

// A parent named by pid alone carries its family only into records made
// before a refresh found it gone.
func TestLineageExecParentMustBeAliveAtTheRecord(t *testing.T) {
	for _, c := range []struct {
		name     string
		at       time.Time
		original bool
		tagged   bool
	}{
		{"exec before the shell was found gone", lineageAt(4), false, true},
		{"exec after the shell was found gone", lineageAt(6), false, false},
		{"original parent was alive at birth", lineageAt(6), true, true},
	} {
		now := lineageAt(0)
		tg := New(lineageConfig(), lineageProcs())
		tg.now = func() time.Time { return now }
		tg.Refresh()
		tg.NoteLineage(Lineage{ParentPID: 500, ChildPID: 600, ChildStart: lineageAt(1), At: lineageAt(1)})
		now = lineageAt(5)
		tg.Refresh() // the shell is not listed: its record is marked exited at lineageAt(5)
		tg.NoteLineage(Lineage{ParentPID: 600, ChildPID: 900, ChildStart: jobStart, OriginalParent: c.original, At: c.at})
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
