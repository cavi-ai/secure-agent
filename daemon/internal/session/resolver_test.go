package session

import (
	"os"
	"path/filepath"
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
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: time.Now().Add(-2 * time.Minute)},
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

// Repo and branch are read from the workspace's .git at resolve time — not
// only when a hook handshake carries them (the audit: repo on 1 of 1,667
// sessions).
func TestGitInfoReadFromWorkspace(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".git", "HEAD"), []byte("ref: refs/heads/feat/session-spine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: ws, StartTime: time.Now().Add(-2 * time.Minute)},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	r.Resolve(&e)
	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	s := sessions[0]
	if s.Repo == "" || s.Branch != "feat/session-spine" {
		t.Fatalf("repo/branch = %q/%q, want non-empty repo + branch from .git/HEAD", s.Repo, s.Branch)
	}
}

// A linked worktree (a .git FILE pointing at the real git dir) still
// resolves its branch — codex and agents often run inside worktrees.
func TestGitInfoFollowsWorktreeLink(t *testing.T) {
	ws := t.TempDir()
	gitDir := filepath.Join(ws, "real-git-dir")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/wt-branch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo, branch := gitInfoFor(ws)
	if branch != "wt-branch" {
		t.Fatalf("branch = %q, want wt-branch via gitdir file", branch)
	}
	if repo == "" {
		t.Fatal("repo must fall back to the workspace basename")
	}
}

// A workspace that is not inside any git tree yields no repo and no branch:
// the basename of a non-repo is noise ("/", ".config"), not identity.
func TestGitInfoNonRepo(t *testing.T) {
	repo, branch := gitInfoFor(t.TempDir())
	if repo != "" || branch != "" {
		t.Fatalf("non-repo = %q/%q, want empty/empty", repo, branch)
	}
	if repo, branch := gitInfoFor(""); repo != "" || branch != "" {
		t.Fatalf("empty workspace = %q/%q, want empty", repo, branch)
	}
}

// A workspace nested inside a checkout resolves to the enclosing repo root,
// not its own basename.
func TestGitInfoWalksUpToGitRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "pkg", "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	repo, branch := gitInfoFor(nested)
	if repo != filepath.Base(root) || branch != "main" {
		t.Fatalf("nested workspace = %q/%q, want %q/main", repo, branch, filepath.Base(root))
	}
}

// Cached resolutions expire: a directory that becomes a repo later must not
// be served the stale empty result forever.
func TestGitInfoCacheExpires(t *testing.T) {
	ws := t.TempDir()
	gitCache = map[string]gitInfo{}
	if repo, _ := gitInfoFor(ws); repo != "" {
		t.Fatalf("pre-repo = %q, want empty", repo)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Still cached within the TTL.
	if repo, _ := gitInfoFor(ws); repo != "" {
		t.Fatalf("cached empty = %q, want empty within TTL", repo)
	}
	// Age the entry past the TTL; the new .git must resolve.
	gitCache[ws] = gitInfo{at: time.Now().Add(-2 * gitCacheTTL)}
	if repo, _ := gitInfoFor(ws); repo != filepath.Base(ws) {
		t.Fatalf("post-TTL = %q, want %q", repo, filepath.Base(ws))
	}
}

// A session created before the resolver started (root started long ago) is
// persisted immediately; a root that is still young is deferred — attributed
// in memory but not persisted until it outlives the floor.
func TestSessionFloorDefersYoungRoots(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/codex", CWD: "/repo", StartTime: time.Now()},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	id := r.Resolve(&e)
	if id == "" {
		t.Fatal("young root must still be attributed in memory")
	}
	if n := len(st.ListSessions(store.SessionFilter{})); n != 0 {
		t.Fatalf("young root persisted %d sessions, want 0 (deferred)", n)
	}
	// The root ages past the floor: the next touch persists it.
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	e2 := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now().Add(2 * time.Minute)}
	if id2 := r.Resolve(&e2); id2 != id {
		t.Fatalf("id changed across touch: %q vs %q", id2, id)
	}
	if n := len(st.ListSessions(store.SessionFilter{})); n != 1 {
		t.Fatalf("sessions = %d, want 1 after floor", n)
	}
}

// A young root that dies before the floor never becomes a row. Regression:
// the promote path treated an untaggable root (dead, pruned by refresh) as
// aged past the floor — the touch throttle guarantees Tag fails first, so
// every young death leaked into the store.
func TestSessionFloorDropsYoungDeaths(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/codex", CWD: "/repo", StartTime: time.Now()},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	if id := r.Resolve(&e); id == "" {
		t.Fatal("must attribute in memory")
	}
	// Root exits young; the tagger prunes it on refresh.
	r.tagger = agents.New(mustConfig(t), fakeProcs{})
	r.tagger.Refresh()
	// A late touch must not promote the dead stub.
	r.mu.Lock()
	r.touchLocked("proc-100-0", time.Now().Add(2*time.Minute).Add(31*time.Second))
	rows := len(st.ListSessions(store.SessionFilter{}))
	r.mu.Unlock()
	if rows != 0 {
		t.Fatalf("sessions = %d, want 0 (young death promoted via Tag-failure)", rows)
	}
	if n := len(st.ListSessions(store.SessionFilter{Status: model.SessionEnded})); n != 0 {
		t.Fatalf("ended rows = %d, want 0", n)
	}
}

// A long-lived process-tree session persists once past the floor wherever its
// workspace lives. Regression guard for the removed /openclaw/ path marker:
// it stopped persistence for established conversations under that path.
func TestAgedWorkspacePersistsRegardlessOfPath(t *testing.T) {
	ws := "/Volumes/workspace/FORKS-PR-ONLY/openclaw/probe-42/workspace"
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/codex", CWD: ws, StartTime: time.Now().Add(-time.Hour)},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	if id := r.Resolve(&e); id == "" {
		t.Fatal("must attribute in memory")
	}
	if n := len(st.ListSessions(store.SessionFilter{})); n != 1 {
		t.Fatalf("aged session persisted %d rows, want 1", n)
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
