package session

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type fakeProcs map[int32]agents.ProcInfo

func (f fakeProcs) List() []agents.ProcInfo {
	out := make([]agents.ProcInfo, 0, len(f))
	for _, p := range f {
		out = append(out, p)
	}
	return out
}

func (f fakeProcs) Info(pid int32) (agents.ProcInfo, bool) {
	p, ok := f[pid]
	return p, ok
}

func testResolver(t *testing.T, procs fakeProcs) (*Resolver, *store.Store) {
	t.Helper()
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg, _ := config.Load("/nonexistent")
	tg := agents.New(cfg, procs)
	tg.Refresh()
	return NewResolver(st, tg), st
}

func TestResolveProcessTreeTier(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: started},
	})

	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	id := r.Resolve(&e)
	if id == "" || e.SessionID != id {
		t.Fatalf("Resolve did not attribute: %q", id)
	}
	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	s := sessions[0]
	if s.Harness != "claude" || s.Workspace != "/repo" || s.Confidence != model.ConfProcessTree {
		t.Fatalf("session = %+v", s)
	}
	if s.RootPID != 100 || s.RootStartedAt == "" {
		t.Fatalf("root identity missing: %+v", s)
	}
}

func TestResolveHookStampedEvent(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now()},
	})
	e := event.Event{Kind: event.KindPluginAction, PID: 100, SessionID: "hook-1", TS: time.Now()}
	if id := r.Resolve(&e); id != "hook-1" {
		t.Fatalf("id = %q, want hook-1", id)
	}
	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 1 || sessions[0].Confidence != model.ConfHook || sessions[0].Harness != "claude" {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestHandshakeRekeysProcessTreeSession(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now()},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	procID := r.Resolve(&e)

	r.HandleHandshake(Handshake{
		SessionID: "hook-abc", Harness: "claude", Workspace: "/repo",
		Repo: "repo", Branch: "main", PID: 100, TS: time.Now(),
	})

	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1 after rekey (%+v)", len(sessions), sessions)
	}
	s := sessions[0]
	if s.ID != "hook-abc" || s.Repo != "repo" || s.Branch != "main" || s.Confidence != model.ConfHook {
		t.Fatalf("session = %+v", s)
	}
	// The old event followed the rekey.
	for _, ev := range st.RecentEvents(10) {
		if ev.SessionID == procID {
			t.Fatalf("event still attributed to rekeyed id %q", procID)
		}
	}
	// New events on the same pid resolve to the hook id.
	e2 := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	if id := r.Resolve(&e2); id != "hook-abc" {
		t.Fatalf("id = %q, want hook-abc", id)
	}
}

func TestSweepEndsSessionsWhoseRootExited(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: time.Now()},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	r.Resolve(&e)

	// Root exits: the tagger's table no longer holds pid 100.
	r.tagger = agents.New(mustConfig(t), fakeProcs{})
	r.tagger.Refresh()
	r.Sweep()

	sessions := st.ListSessions(store.SessionFilter{Status: model.SessionEnded})
	if len(sessions) != 1 {
		t.Fatalf("ended = %d, want 1 (%+v)", len(sessions), st.ListSessions(store.SessionFilter{}))
	}
}

func mustConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, _ := config.Load("/nonexistent")
	return cfg
}

// The join: a transcript sighting merges into the process-tree session for the
// same harness+workspace, rekeying its events onto the conversation id and
// filling harness/workspace so the session is never nameless. This is what
// makes "claude · repo@branch · timeline" possible.
func TestTranscriptSessionJoinsProcessTreeSession(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now()},
	})
	// A process-tree session is created first (an OS event arrives).
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	procID := r.Resolve(&e)
	if procID == "" {
		t.Fatal("process-tree session not created")
	}

	// Then the transcript names the conversation for the same workspace.
	r.NoteTranscriptSession("conv-abc", "claude", "/repo", time.Now())

	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1 (joined, not duplicated): %+v", len(sessions), sessions)
	}
	s := sessions[0]
	if s.ID != "conv-abc" || s.Harness != "claude" || s.Workspace != "/repo" {
		t.Fatalf("joined session = %+v", s)
	}
	// The earlier OS event followed the rekey.
	for _, ev := range st.RecentEvents(10) {
		if ev.SessionID == procID {
			t.Fatalf("event still on provisional id %q", procID)
		}
	}
}

// A transcript seen BEFORE the process tree is adopted: the process-tree
// resolve must reuse the conversation id, not mint a second session.
func TestProcessTreeAdoptsPriorTranscriptSession(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now()},
	})
	r.NoteTranscriptSession("conv-xyz", "claude", "/repo", time.Now())
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	id := r.Resolve(&e)
	if id != "conv-xyz" {
		t.Fatalf("resolved id = %q, want conv-xyz (adopted)", id)
	}
	if n := len(st.ListSessions(store.SessionFilter{})); n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}
}
