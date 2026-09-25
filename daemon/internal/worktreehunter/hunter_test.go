package worktreehunter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// isolateGit points git at an empty config and home so fixtures never pick
// up the developer's signing, hooks or global excludes.
func isolateGit(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@example.com")
	return home
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return runEnv(t, nil, dir, args...)
}

func runEnv(t *testing.T, env []string, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, file, content, msg string) {
	t.Helper()
	write(t, filepath.Join(dir, file), content)
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", msg)
}

// fixture is a repository with an origin, cloned to main.
type fixture struct {
	root, origin, main string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	f := fixture{root: root, origin: filepath.Join(root, "origin.git"), main: filepath.Join(root, "repo")}
	run(t, root, "init", "-q", "--bare", "-b", "main", f.origin)
	run(t, root, "clone", "-q", f.origin, f.main)
	run(t, f.main, "checkout", "-q", "-b", "main")
	commit(t, f.main, ".gitignore", ".env\nnode_modules/\n", "ignore")
	commit(t, f.main, "base.txt", "l1\nl2\nl3\nl4\nl5\nl6\nl7\n", "base")
	run(t, f.main, "push", "-q", "-u", "origin", "main")
	run(t, f.main, "remote", "set-head", "origin", "main")
	return f
}

// worktree adds <main>/.worktrees/<name> on a new branch from main.
func (f fixture) worktree(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(f.main, ".worktrees", name)
	run(t, f.main, "worktree", "add", "-q", "-b", "feat/"+name, p, "main")
	return p
}

// age backdates a worktree's index so only HEAD time and sessions count.
func age(t *testing.T, wt string, d time.Duration) {
	t.Helper()
	old := time.Now().Add(-d)
	idx := strings.TrimSpace(run(t, wt, "rev-parse", "--git-path", "index"))
	if !filepath.IsAbs(idx) {
		idx = filepath.Join(wt, idx)
	}
	if err := os.Chtimes(idx, old, old); err != nil {
		t.Fatal(err)
	}
}

type memStore struct {
	mu       sync.Mutex
	repos    map[string]model.WorktreeRepo
	activity []model.WorkspaceActivity
	audit    []store.AuditEntry
	cleanup  []model.CleanupEntry
	scan     map[string]scanEntry
}

func newMemStore() *memStore { return &memStore{repos: map[string]model.WorktreeRepo{}} }

func (m *memStore) WorktreeRepos() []model.WorktreeRepo {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.WorktreeRepo
	for _, r := range m.repos {
		out = append(out, r)
	}
	return out
}

func (m *memStore) UpsertWorktreeRepo(path, source string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.repos[path]
	if !ok {
		r = model.WorktreeRepo{Path: path, Source: source, FirstSeen: at}
	}
	if source == model.RepoSourceManual {
		r.Source, r.Hidden = source, false
	}
	r.LastScan = at
	m.repos[path] = r
}

func (m *memStore) SetWorktreeRepoHidden(path string, hidden bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.repos[path]
	if ok {
		r.Hidden = hidden
		m.repos[path] = r
	}
	return ok
}

func (m *memStore) WorkspaceActivity() []model.WorkspaceActivity { return m.activity }

type scanEntry struct {
	body []byte
	at   time.Time
}

func (m *memStore) ScanCache(name string) ([]byte, time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.scan[name]
	return e.body, e.at, ok
}

func (m *memStore) PutScanCache(name string, body []byte, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scan == nil {
		m.scan = map[string]scanEntry{}
	}
	m.scan[name] = scanEntry{body: append([]byte(nil), body...), at: at}
}

func (m *memStore) PutCleanup(e model.CleanupEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanup = append(m.cleanup, e)
}

func (m *memStore) PutAudit(a store.AuditEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, a)
}

func findRow(t *testing.T, rep ScanReport, path string) Worktree {
	t.Helper()
	for _, r := range rep.Repos {
		for _, w := range r.Worktrees {
			if w.Path == path {
				return w
			}
		}
	}
	t.Fatalf("no row for %s in report: %+v", path, rep)
	return Worktree{}
}

func wantState(t *testing.T, w Worktree, state, reason string) {
	t.Helper()
	if w.State != state {
		t.Errorf("%s: state %q, want %q (reasons %q)", filepath.Base(w.Path), w.State, state, w.Reasons)
		return
	}
	if reason != "" && !strings.Contains(strings.Join(w.Reasons, " | "), reason) {
		t.Errorf("%s: reasons %q lack %q", filepath.Base(w.Path), w.Reasons, reason)
	}
}

func TestScanClassifiesEveryRule(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	merged := f.worktree(t, "merged")
	commit(t, merged, "a.txt", "a\n", "a")
	run(t, f.main, "merge", "-q", "--no-ff", "-m", "merge a", "feat/merged")

	// The squash lands after main changed a line two above the branch's
	// edit: the squash commit's diff context differs from the branch's.
	squash := f.worktree(t, "squash")
	commit(t, squash, "b1.txt", "b1\n", "b1")
	commit(t, squash, "base.txt", "l1\nl2\nl3\nl4\nl5 branch\nl6\nl7\n", "b2")
	commit(t, f.main, "base.txt", "l1\nl2\nl3 main\nl4\nl5\nl6\nl7\n", "main edits nearby")
	run(t, f.main, "merge", "-q", "--squash", "feat/squash")
	run(t, f.main, "commit", "-q", "-m", "squash b")
	commit(t, f.main, "later.txt", "later\n", "main moves on")
	run(t, f.main, "push", "-q", "origin", "main")

	dirty := f.worktree(t, "dirty")
	write(t, filepath.Join(dirty, "base.txt"), "edited\n")

	untracked := f.worktree(t, "untracked")
	write(t, filepath.Join(untracked, "new.txt"), "new\n")

	unpushed := f.worktree(t, "unpushed")
	commit(t, unpushed, "d.txt", "d\n", "d")

	pushedActive := f.worktree(t, "pushed-active")
	commit(t, pushedActive, "e.txt", "e\n", "e")
	run(t, pushedActive, "push", "-q", "-u", "origin", "feat/pushed-active")

	pushedIdle := f.worktree(t, "pushed-idle")
	write(t, filepath.Join(pushedIdle, "f.txt"), "f\n")
	run(t, pushedIdle, "add", "-A")
	runEnv(t, []string{"GIT_COMMITTER_DATE=" + time.Now().Add(-40*24*time.Hour).Format(time.RFC3339)},
		pushedIdle, "commit", "-q", "-m", "f")
	run(t, pushedIdle, "push", "-q", "-u", "origin", "feat/pushed-idle")
	age(t, pushedIdle, 40*24*time.Hour)

	locked := f.worktree(t, "locked")
	run(t, f.main, "worktree", "lock", "--reason", "agent busy", locked)

	missing := f.worktree(t, "missing")
	if err := os.RemoveAll(missing); err != nil {
		t.Fatal(err)
	}

	env := f.worktree(t, "env")
	write(t, filepath.Join(env, ".env"), "TOKEN=[REDACTED]\n")

	nodeMods := f.worktree(t, "nodemods")
	write(t, filepath.Join(nodeMods, "node_modules", "x", "index.js"), "x\n")

	detached := filepath.Join(f.main, ".worktrees", "detached")
	run(t, f.main, "worktree", "add", "-q", "--detach", detached, "main")
	commit(t, detached, "g.txt", "g\n", "g")

	inUse := f.worktree(t, "in-use")

	stashed := f.worktree(t, "stashed")
	write(t, filepath.Join(stashed, "base.txt"), "stash me\n")
	run(t, stashed, "stash", "-q")

	gone := f.worktree(t, "gone-upstream")
	commit(t, gone, "h.txt", "h\n", "h")
	run(t, gone, "push", "-q", "-u", "origin", "feat/gone-upstream")
	run(t, f.main, "merge", "-q", "--no-ff", "-m", "merge h", "feat/gone-upstream")
	run(t, f.main, "push", "-q", "origin", "main", ":feat/gone-upstream")
	run(t, f.main, "fetch", "-q", "--prune")

	orphan := f.worktree(t, "orphan")
	adminDir := strings.TrimSpace(run(t, orphan, "rev-parse", "--absolute-git-dir"))
	if err := os.RemoveAll(adminDir); err != nil {
		t.Fatal(err)
	}

	st := newMemStore()
	st.activity = []model.WorkspaceActivity{
		{Workspace: filepath.Join(inUse, "sub"), LastSeen: time.Now(), Live: true},
		{Workspace: f.main, LastSeen: time.Now()},
	}
	h := New(st, home, Options{})
	// Two days on: past the 24-hour grace every fresh fixture would sit in.
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	rep := h.Report(ctx, true)
	if len(rep.Errors) != 0 {
		t.Fatalf("scan errors: %v", rep.Errors)
	}

	wantState(t, findRow(t, rep, f.main), StateMain, "")
	wantState(t, findRow(t, rep, merged), StateRemove, "contained in origin/main")
	wantState(t, findRow(t, rep, squash), StateRemove, "(squash)")
	wantState(t, findRow(t, rep, dirty), StateKeep, "1 uncommitted change")
	wantState(t, findRow(t, rep, untracked), StateKeep, "1 untracked file")
	wantState(t, findRow(t, rep, unpushed), StateReview, "1 commit on no remote and not in origin/main")
	wantState(t, findRow(t, rep, pushedActive), StateKeep, "not merged; active 2 days ago")
	wantState(t, findRow(t, rep, pushedIdle), StateRemove, "every commit is on a remote; idle 42 days")
	wantState(t, findRow(t, rep, locked), StateKeep, "locked: agent busy")
	wantState(t, findRow(t, rep, missing), StatePrune, "directory is gone")
	wantState(t, findRow(t, rep, env), StateReview, "ignored files that only live here: .env (17 B)")
	wantState(t, findRow(t, rep, nodeMods), StateRemove, "")
	wantState(t, findRow(t, rep, detached), StateKeep, "detached HEAD with 1 commit on no branch")
	wantState(t, findRow(t, rep, inUse), StateKeep, "an agent session is live here")
	wantState(t, findRow(t, rep, orphan), StateReview, "not registered with git")
	wantState(t, findRow(t, rep, stashed), StateReview, "1 stash on this branch")

	g := findRow(t, rep, gone)
	wantState(t, g, StateRemove, "contained in origin/main")
	if !g.UpstreamGone || !g.Stale {
		t.Errorf("gone-upstream: upstream_gone=%v stale=%v, want both", g.UpstreamGone, g.Stale)
	}
	if w := findRow(t, rep, pushedIdle); !w.Stale || w.IdleDays < 39 {
		t.Errorf("pushed-idle: stale=%v idle=%d", w.Stale, w.IdleDays)
	}
	if w := findRow(t, rep, pushedActive); w.Stale {
		t.Errorf("pushed-active marked stale")
	}

	if rep.Summary.Repos != 1 || rep.Summary.Worktrees != 16 {
		t.Errorf("summary = %+v, want 1 repo and 16 worktrees", rep.Summary)
	}
	if got := st.repos[f.main]; got.Source != model.RepoSourceSession {
		t.Errorf("saved repo = %+v, want source session", got)
	}
}

// The scan must never rewrite a worktree's index: GIT_OPTIONAL_LOCKS=0 keeps
// `git status` from refreshing it under an agent.
func TestScanLeavesIndexUntouched(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "touched")
	// Same content, new mtime: a plain `git status` would refresh the index.
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(wt, "base.txt"), later, later); err != nil {
		t.Fatal(err)
	}
	age(t, wt, 48*time.Hour)
	idx := strings.TrimSpace(run(t, wt, "rev-parse", "--git-path", "index"))
	if !filepath.IsAbs(idx) {
		idx = filepath.Join(wt, idx)
	}
	before, _ := os.Stat(idx)

	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	New(st, home, Options{}).Report(context.Background(), true)

	after, _ := os.Stat(idx)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("scan rewrote the index: %v -> %v", before.ModTime(), after.ModTime())
	}
}

func TestDiscoverSeeds(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "a")

	// A second repo reachable only through the Codex app's worktree dir.
	other := fixture{origin: filepath.Join(f.root, "other.git"), main: filepath.Join(f.root, "other")}
	run(t, f.root, "init", "-q", "-b", "main", other.main)
	commit(t, other.main, "x.txt", "x\n", "x")
	codexWT := filepath.Join(home, ".codex", "worktrees", "ab12", "other")
	run(t, other.main, "worktree", "add", "-q", "-b", "codex/x", codexWT)

	// A third repo found only under a configured scan root, depth 2.
	third := filepath.Join(f.root, "roots", "team", "third")
	run(t, f.root, "init", "-q", "-b", "main", third)

	d := discover(context.Background(), discoverInput{
		Home:  home,
		Roots: []string{filepath.Join(f.root, "roots")},
		Workspaces: []model.WorkspaceActivity{
			{Workspace: filepath.Join(f.main, "sub", "dir")}, // subdirectory of main
			{Workspace: wt}, // linked worktree: same repo
			{Workspace: filepath.Join(f.main, ".worktrees", "deleted-x")}, // deleted workspace: walks up
			{Workspace: "/nonexistent/place"},
		},
	})
	got := map[string]string{}
	for _, r := range d.Repos {
		got[r.Ref.Main] = r.Source
	}
	thirdCanon, _ := filepath.EvalSymlinks(third)
	want := map[string]string{
		f.main:     model.RepoSourceSession,
		other.main: model.RepoSourceScan,
		thirdCanon: model.RepoSourceRoot,
	}
	if len(got) != len(want) {
		t.Fatalf("repos = %v, want %v", got, want)
	}
	for p, src := range want {
		if got[p] != src {
			t.Errorf("repo %s source %q, want %q (all %v)", p, got[p], src, got)
		}
	}

	// Hidden repos are dropped wherever they are found.
	d = discover(context.Background(), discoverInput{
		Home:       home,
		Saved:      []model.WorktreeRepo{{Path: f.main, Source: model.RepoSourceManual, Hidden: true}},
		Workspaces: []model.WorkspaceActivity{{Workspace: wt}},
	})
	for _, r := range d.Repos {
		if r.Ref.Main == f.main {
			t.Fatalf("hidden repo discovered: %+v", d.Repos)
		}
	}
}

func TestAddAndHideRepo(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	st := newMemStore()
	h := New(st, home, Options{})

	if _, err := h.AddRepo("relative/path"); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := h.AddRepo(f.root); err != ErrNotRepo {
		t.Fatalf("non-repo add err = %v, want ErrNotRepo", err)
	}
	main, err := h.AddRepo(filepath.Join(f.main, "sub"))
	if err != nil || main != f.main {
		t.Fatalf("AddRepo = %q, %v; want %q", main, err, f.main)
	}
	if r := st.repos[f.main]; r.Source != model.RepoSourceManual {
		t.Fatalf("saved = %+v", r)
	}
	if rep := h.Report(context.Background(), false); rep.Summary.Repos != 1 {
		t.Fatalf("manual repo not scanned: %+v", rep.Summary)
	}
	if !h.HideRepo(f.main) {
		t.Fatal("HideRepo reported unknown repo")
	}
	if rep := h.Report(context.Background(), false); rep.Summary.Repos != 0 || rep.Cached {
		t.Fatalf("hidden repo still reported (or stale cache): %+v cached=%v", rep.Summary, rep.Cached)
	}
}

func TestReportCaches(t *testing.T) {
	home := isolateGit(t)
	h := New(newMemStore(), home, Options{})
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	if r := h.Report(context.Background(), false); r.Cached {
		t.Fatal("first report cached")
	}
	if r := h.Report(context.Background(), false); !r.Cached {
		t.Fatal("second report within TTL not cached")
	}
	if r := h.Report(context.Background(), true); !r.Cached {
		t.Fatal("refresh inside minRescan rescanned")
	}
	now = now.Add(minRescan + time.Second)
	if r := h.Report(context.Background(), true); r.Cached {
		t.Fatal("refresh after minRescan served the cache")
	}
	now = now.Add(cacheTTL + time.Second)
	stale := h.Report(context.Background(), false)
	if !stale.Cached || !stale.Refreshing {
		t.Fatalf("an expired scan must answer while a rescan runs: cached=%v refreshing=%v", stale.Cached, stale.Refreshing)
	}
	h.bgWG.Wait()
	if r := h.Report(context.Background(), false); r.Refreshing || !r.GeneratedAt.After(stale.GeneratedAt) {
		t.Fatalf("the background rescan did not replace the scan: refreshing=%v at %v (was %v)", r.Refreshing, r.GeneratedAt, stale.GeneratedAt)
	}
}

// A worktree touched in the last day is never remove, merged or not: a
// fresh one an agent is about to use has no commits and reads as merged.
func TestClassifyActiveGrace(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		ago   time.Duration
		state string
		stale bool
	}{
		{time.Hour, StateKeep, false},
		{23 * time.Hour, StateKeep, false},
		{25 * time.Hour, StateRemove, true},
	} {
		w := Worktree{Merged: mergedAncestor}
		classify(&w, facts{DefaultBranch: "origin/main", IndexTime: now.Add(-c.ago)}, now, 14*24*time.Hour)
		if w.State != c.state || w.Stale != c.stale {
			t.Errorf("merged, touched %v ago: state %s stale %v, want %s %v (%q)", c.ago, w.State, w.Stale, c.state, c.stale, w.Reasons)
		}
		if c.state == StateKeep && !strings.Contains(strings.Join(w.Reasons, " "), "active in the last 24 hours") {
			t.Errorf("grace reason missing: %q", w.Reasons)
		}
	}
}

func TestGitEnvIsReadOnly(t *testing.T) {
	cmd := gitCommand(context.Background(), "/x", "status")
	joined := strings.Join(cmd.Env, "\n")
	for _, want := range []string{"GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("git env lacks %s", want)
		}
	}
	if !strings.Contains(strings.Join(cmd.Args, " "), "core.fsmonitor=false") {
		t.Errorf("git args lack core.fsmonitor=false: %v", cmd.Args)
	}
}
