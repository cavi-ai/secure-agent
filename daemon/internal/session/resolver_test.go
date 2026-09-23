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

func testResolver(t *testing.T, procs agents.ProcSource) (*Resolver, *store.Store) {
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

// A tagged child process (a shell the harness spawned, in another cwd) joins
// its harness's session: one row, keyed, rooted and scoped on the harness.
func TestChildProcessJoinsHarnessSession(t *testing.T) {
	rootStart := time.Now().Add(-time.Hour)
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/opt/homebrew/bin/codex", CWD: "/repo", StartTime: rootStart},
		200: {PID: 200, PPID: 100, Exe: "/bin/zsh", CWD: "/repo/sub", StartTime: rootStart.Add(time.Minute)},
	})
	child := resolvePID(t, r, 200)
	root := resolvePID(t, r, 100)
	want := ProcSessionID(100, rootStart)
	if child != want || root != want {
		t.Fatalf("child=%q root=%q, want both %q", child, root, want)
	}
	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1: %+v", len(sessions), sessions)
	}
	s := sessions[0]
	if s.RootPID != 100 || s.Workspace != "/repo" || s.RootStartedAt != rootStart.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("session = %+v, want root 100 in /repo started %s", s, rootStart)
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

// flakyProcs serves every pid through Info but leaves hidden pids out of
// List: a process-table sample that missed a live process.
type flakyProcs struct {
	procs  fakeProcs
	hidden map[int32]bool
}

func (f *flakyProcs) List() []agents.ProcInfo {
	out := make([]agents.ProcInfo, 0, len(f.procs))
	for pid, p := range f.procs {
		if !f.hidden[pid] {
			out = append(out, p)
		}
	}
	return out
}

func (f *flakyProcs) Info(pid int32) (agents.ProcInfo, bool) {
	return f.procs.Info(pid)
}

func TestSweepEndsSessionOnlyWhenRootConfirmedGone(t *testing.T) {
	src := &flakyProcs{
		procs:  fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now().Add(-time.Hour)}},
		hidden: map[int32]bool{},
	}
	r, st := testResolver(t, src)
	id := resolvePID(t, r, 100)
	// A restarted daemon knows the session only from the store.
	restarted := NewResolver(st, r.tagger)

	status := func() string {
		got, _ := st.GetSession(id)
		return got.Status
	}

	src.hidden[100] = true
	r.tagger.Refresh()
	r.Sweep()
	restarted.Sweep()
	if s := status(); s != model.SessionActive {
		t.Fatalf("status = %q after one missed sample, want active", s)
	}
	if r.byRoot[100] != id {
		t.Fatalf("byRoot[100] = %q, want %q", r.byRoot[100], id)
	}

	delete(src.procs, 100)
	r.tagger.Refresh()
	restarted.Sweep()
	if s := status(); s != model.SessionEnded {
		t.Fatalf("status = %q with root gone (store sweep), want ended", s)
	}
	r.Sweep()
	if _, ok := r.byRoot[100]; ok {
		t.Fatal("byRoot still holds the ended root")
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
	repo, branch := GitInfoFor(ws)
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
	repo, branch := GitInfoFor(t.TempDir())
	if repo != "" || branch != "" {
		t.Fatalf("non-repo = %q/%q, want empty/empty", repo, branch)
	}
	if repo, branch := GitInfoFor(""); repo != "" || branch != "" {
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
	repo, branch := GitInfoFor(nested)
	if repo != filepath.Base(root) || branch != "main" {
		t.Fatalf("nested workspace = %q/%q, want %q/main", repo, branch, filepath.Base(root))
	}
}

// Cached resolutions expire: a directory that becomes a repo later must not
// be served the stale empty result forever.
func TestGitInfoCacheExpires(t *testing.T) {
	ws := t.TempDir()
	gitCache = map[string]gitInfo{}
	if repo, _ := GitInfoFor(ws); repo != "" {
		t.Fatalf("pre-repo = %q, want empty", repo)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Still cached within the TTL.
	if repo, _ := GitInfoFor(ws); repo != "" {
		t.Fatalf("cached empty = %q, want empty within TTL", repo)
	}
	// Age the entry past the TTL; the new .git must resolve.
	gitCache[ws] = gitInfo{at: time.Now().Add(-2 * gitCacheTTL)}
	if repo, _ := GitInfoFor(ws); repo != filepath.Base(ws) {
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

// orchestratorTree is an openclaw family root (100) whose node child (101)
// spawns a codex run (102): the codex tag chain stops at codex itself.
func orchestratorTree() fakeProcs {
	started := time.Now().Add(-time.Hour)
	return fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/Users/u/.openclaw/node/bin/node", CWD: "/ws", StartTime: started},
		101: {PID: 101, PPID: 100, Exe: "/Users/u/.openclaw/node/bin/node", CWD: "/ws", StartTime: started},
		102: {PID: 102, PPID: 101, Exe: "/opt/homebrew/bin/codex", CWD: "/ws/run", StartTime: started},
	}
}

func resolvePID(t *testing.T, r *Resolver, pid int32) string {
	t.Helper()
	e := event.Event{Kind: event.KindFileOpen, PID: pid, TS: time.Now()}
	id := r.Resolve(&e)
	if id == "" {
		t.Fatalf("pid %d not attributed", pid)
	}
	return id
}

func TestOrchestratedRunNestsUnderOrchestrator(t *testing.T) {
	r, st := testResolver(t, orchestratorTree())
	parent := resolvePID(t, r, 100)
	child := resolvePID(t, r, 102)
	got, ok := st.GetSession(child)
	if !ok || got.Harness != "codex" || got.ParentID != parent {
		t.Fatalf("codex session = %+v, %v; want parent %q", got, ok, parent)
	}
}

// The orchestrator family's session is the one held by its highest ancestor,
// even when a nearer family member resolved a session of its own.
func TestOrchestratorParentIsFamilyRootSession(t *testing.T) {
	r, st := testResolver(t, orchestratorTree())
	parent := resolvePID(t, r, 100)
	resolvePID(t, r, 101)
	child := resolvePID(t, r, 102)
	if got, _ := st.GetSession(child); got.ParentID != parent {
		t.Fatalf("codex parent = %q, want %q", got.ParentID, parent)
	}
}

// No session is invented for an orchestrator family that has none yet.
func TestOrchestratorWithoutSessionLeavesParentEmpty(t *testing.T) {
	r, st := testResolver(t, orchestratorTree())
	child := resolvePID(t, r, 102)
	if got, ok := st.GetSession(child); !ok || got.ParentID != "" {
		t.Fatalf("codex session = %+v, %v; want no parent", got, ok)
	}
}

func TestRootWithoutOtherHarnessHasNoParent(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	r, st := testResolver(t, fakeProcs{
		300: {PID: 300, PPID: 1, Exe: "/bin/zsh", StartTime: started},
		301: {PID: 301, PPID: 300, Exe: "/opt/homebrew/bin/codex", CWD: "/a", StartTime: started},
		302: {PID: 302, PPID: 301, Exe: "/opt/homebrew/bin/codex", CWD: "/b", StartTime: started},
	})
	for _, pid := range []int32{301, 302} {
		id := resolvePID(t, r, pid)
		if got, _ := st.GetSession(id); got.ParentID != "" {
			t.Fatalf("pid %d parent = %q, want none", pid, got.ParentID)
		}
	}
}

// An IDE is infrastructure, not an orchestrator: an agent started from its
// terminal stays top-level even when the IDE has a session.
func TestInfraAncestorIsNotOrchestrator(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	r, st := testResolver(t, fakeProcs{
		400: {PID: 400, PPID: 1, Exe: "/Applications/Cursor.app/Contents/MacOS/Cursor", StartTime: started},
		401: {PID: 401, PPID: 400, Exe: "/bin/zsh", StartTime: started},
		402: {PID: 402, PPID: 401, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: started},
	})
	resolvePID(t, r, 400)
	child := resolvePID(t, r, 402)
	if got, _ := st.GetSession(child); got.ParentID != "" {
		t.Fatalf("claude parent = %q, want none", got.ParentID)
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

// A second transcript id in the same workspace is a sibling conversation:
// the first transcript session must NOT be rekeyed onto it. Only
// process-tree (provisional) sessions are eligible for the rekey join.
func TestSecondTranscriptIdIsSiblingNotRekey(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now()},
	})
	now := time.Now()
	r.NoteTranscriptSession("conv-1", "claude", "/repo", now)
	r.NoteTranscriptSession("conv-2", "claude", "/repo", now.Add(time.Minute))

	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 sibling rows: %+v", len(sessions), sessions)
	}
	for _, s := range sessions {
		if s.ID != "conv-1" && s.ID != "conv-2" {
			t.Fatalf("unexpected session id %q — a transcript session was rekeyed", s.ID)
		}
	}
}

// A process-tree session still rekeys onto a transcript sighting (the join),
// and a LATER transcript id leaves the joined row alone.
func TestTranscriptJoinThenSiblingStaysPut(t *testing.T) {
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now()},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	procID := r.Resolve(&e)
	if procID == "" {
		t.Fatal("process-tree session not created")
	}
	r.NoteTranscriptSession("conv-1", "claude", "/repo", time.Now())
	r.NoteTranscriptSession("conv-2", "claude", "/repo", time.Now().Add(time.Minute))

	sessions := st.ListSessions(store.SessionFilter{})
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 (joined conv-1 + sibling conv-2): %+v", len(sessions), sessions)
	}
	ids := map[string]bool{}
	for _, s := range sessions {
		ids[s.ID] = true
	}
	if !ids["conv-1"] || !ids["conv-2"] {
		t.Fatalf("session ids = %v, want conv-1 and conv-2", ids)
	}
	for _, ev := range st.RecentEvents(10) {
		if ev.SessionID == procID {
			t.Fatalf("event still on provisional id %q", procID)
		}
	}
}
