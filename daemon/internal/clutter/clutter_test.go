package clutter

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type memStore struct {
	mu       sync.Mutex
	ledger   []model.CleanupEntry
	activity []model.WorkspaceActivity
	scan     map[string]scanEntry
}

func (m *memStore) PutCleanup(e model.CleanupEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ledger = append(m.ledger, e)
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

func mk(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

// machine lays out a home with tool and app caches and a workspace with a
// repository, a linked worktree inside it and a workspace-level quarantine.
type machine struct {
	home, ws, repo, wt string
	places             []Place
}

func newMachine(t *testing.T) machine {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	m := machine{home: filepath.Join(root, "home"), ws: filepath.Join(root, "work", "team")}
	m.repo = filepath.Join(m.ws, "app")
	m.wt = filepath.Join(m.repo, ".worktrees", "feat")
	mk(t, filepath.Join(m.repo, ".tmp", "evidence.log"), 3000)
	mk(t, filepath.Join(m.repo, "node_modules", "x", "index.js"), 8000)
	mk(t, filepath.Join(m.repo, "packages", "ui", "node_modules", "y.js"), 2000)
	mk(t, filepath.Join(m.repo, "src", "main.go"), 100)
	mk(t, filepath.Join(m.wt, ".tmp", "wt.log"), 1000)
	mk(t, filepath.Join(m.wt, ".quarantine", "old.bin"), 5000)
	mk(t, filepath.Join(m.ws, ".quarantine", "stale.zip"), 7000)
	mk(t, filepath.Join(m.home, ".npm", "_cacache", "index", "a"), 9000)
	mk(t, filepath.Join(m.home, ".cache", "uv", "wheel"), 4000)
	mk(t, filepath.Join(m.home, ".cache", "huggingface", "model.bin"), 6000)
	mk(t, filepath.Join(m.home, ".cache", "someapp", "blob"), 1500)
	mk(t, filepath.Join(m.home, "Library", "Caches", "com.example.App", "c.db"), 2500)
	// A real repository: only what git ignores is offered; build/ here is
	// tracked source and must never be offered for the Trash.
	mk(t, filepath.Join(m.repo, "build", "release.sh"), 50)
	if err := os.WriteFile(filepath.Join(m.repo, ".gitignore"), []byte("node_modules/\n.tmp/\n.quarantine/\n.worktrees/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", m.repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+filepath.Join(root, "gitconfig"), "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("add", ".gitignore", "build", "src")
	git("commit", "-q", "-m", "base")
	m.places = []Place{{Path: m.repo, Project: m.repo}, {Path: m.wt, Project: m.repo, Worktree: m.wt}}
	return m
}

func (m machine) clutter(st *memStore) *Clutter {
	c := New(st, m.home, func(context.Context) []Place { return m.places })
	c.goos = "darwin"
	// Only the fake home's bin: a test never finds (or runs) a real tool.
	c.binDirs = []string{filepath.Join(m.home, ".local", "bin")}
	return c
}

func byPath(t *testing.T, rep ClutterReport, p string) ClutterItem {
	t.Helper()
	for _, it := range rep.Items {
		if it.Path == p {
			return it
		}
	}
	t.Fatalf("no item for %s in %+v", p, rep.Items)
	return ClutterItem{}
}

func TestInventoryKindsProjectsAndLiveSessions(t *testing.T) {
	m := newMachine(t)
	t.Setenv("PATH", "/usr/bin:/bin") // no real tools: caches fall back to Trash
	st := &memStore{activity: []model.WorkspaceActivity{{Workspace: filepath.Join(m.wt, "sub"), Live: true}}}
	c := m.clutter(st)
	rep := c.Report(context.Background(), true)

	want := map[string]struct{ kind, project, action string }{
		filepath.Join(m.repo, ".tmp"):                                 {KindTmp, m.repo, ActionTrash},
		filepath.Join(m.repo, "node_modules"):                         {KindRepoCache, m.repo, ActionTrash},
		filepath.Join(m.repo, "packages", "ui", "node_modules"):       {KindRepoCache, m.repo, ActionTrash},
		filepath.Join(m.repo, "build"):                                {KindRepoCache, m.repo, ActionNone},
		filepath.Join(m.wt, ".tmp"):                                   {KindTmp, m.repo, ActionNone},
		filepath.Join(m.wt, ".quarantine"):                            {KindQuarantine, m.repo, ActionNone},
		filepath.Join(m.ws, ".quarantine"):                            {KindQuarantine, "", ActionTrash},
		filepath.Join(m.home, ".npm", "_cacache"):                     {KindToolCache, "", ActionTrash},
		filepath.Join(m.home, ".cache", "uv"):                         {KindToolCache, "", ActionTrash},
		filepath.Join(m.home, ".cache", "huggingface"):                {KindToolCache, "", ActionNone},
		filepath.Join(m.home, ".cache", "someapp"):                    {KindAppCache, "", ActionTrash},
		filepath.Join(m.home, "Library", "Caches", "com.example.App"): {KindAppCache, "", ActionTrash},
	}
	for p, w := range want {
		it := byPath(t, rep, p)
		if it.Kind != w.kind || it.Project != w.project || it.Action != w.action {
			t.Errorf("%s: kind %s project %q action %s, want %s %q %s", p, it.Kind, it.Project, it.Action, w.kind, w.project, w.action)
		}
	}
	if len(rep.Items) != len(want) {
		t.Errorf("items = %d, want %d: %+v", len(rep.Items), len(want), rep.Items)
	}
	if it := byPath(t, rep, filepath.Join(m.wt, ".tmp")); it.Note != "an agent session is live here" {
		t.Errorf("live worktree note = %q", it.Note)
	}
	if it := byPath(t, rep, filepath.Join(m.repo, "build")); !strings.Contains(it.Note, "not a cache") {
		t.Errorf("tracked build/ note = %q", it.Note)
	}
	if !rep.Sizing {
		t.Fatal("first report must be sizing")
	}

	c.sizeWG.Wait()
	rep = c.Report(context.Background(), false)
	nm := byPath(t, rep, filepath.Join(m.repo, "node_modules"))
	if rep.Sizing || nm.SizeBytes < 8000 || nm.Files != 1 || nm.LastTouched == nil {
		t.Fatalf("sized node_modules = %+v (sizing %v)", nm, rep.Sizing)
	}
	if rep.Items[0].SizeBytes < rep.Items[len(rep.Items)-1].SizeBytes {
		t.Fatal("items must list biggest first")
	}
	var projBytes, kindBytes int64
	for _, p := range rep.Projects {
		projBytes += p.Bytes
	}
	for _, k := range rep.Kinds {
		kindBytes += k.Bytes
	}
	if projBytes != kindBytes || len(rep.Kinds) != 5 || rep.Projects[0].Bytes < rep.Projects[len(rep.Projects)-1].Bytes {
		t.Fatalf("totals: projects %d kinds %d: %+v %+v", projBytes, kindBytes, rep.Projects, rep.Kinds)
	}
}

func TestTrashMovesToTheVolumeTrashAndBooksIt(t *testing.T) {
	m := newMachine(t)
	t.Setenv("PATH", "/usr/bin:/bin")
	st := &memStore{activity: []model.WorkspaceActivity{{Workspace: m.wt, Live: true}}}
	c := m.clutter(st)
	c.Report(context.Background(), true)

	target := filepath.Join(m.repo, ".tmp")
	res, err := c.Trash(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("trashed directory still in place")
	}
	if !strings.HasPrefix(res.TrashAt, filepath.Join(m.home, ".Trash")+"/") || res.Bytes < 3000 {
		t.Fatalf("result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(res.TrashAt, "evidence.log")); err != nil {
		t.Fatalf("contents not in the Trash: %v", err)
	}
	if len(st.ledger) != 1 || st.ledger[0].Action != "trash:tmp" || st.ledger[0].Repo != m.repo || st.ledger[0].Bytes != res.Bytes {
		t.Fatalf("ledger = %+v", st.ledger)
	}

	// A second .tmp with the same name lands beside the first.
	mk(t, filepath.Join(m.ws, ".tmp", "x"), 10)
	res2, err := c.Trash(context.Background(), filepath.Join(m.ws, ".tmp"))
	if err != nil || res2.TrashAt == res.TrashAt {
		t.Fatalf("second trash: %+v, %v", res2, err)
	}

	for _, p := range []string{
		filepath.Join(m.wt, ".tmp"),                    // live agent session
		filepath.Join(m.repo, "src"),                   // not an inventory item
		filepath.Join(m.home, ".cache", "huggingface"), // list-only
		target, // already trashed
	} {
		if _, err := c.Trash(context.Background(), p); !errors.Is(err, ErrNotInInventory) {
			t.Errorf("Trash(%s) err = %v, want ErrNotInInventory", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(m.wt, ".tmp", "wt.log")); err != nil {
		t.Fatal("a refused trash moved files")
	}
}

func TestCleanRunsTheToolsOwnCommand(t *testing.T) {
	m := newMachine(t)
	t.Setenv("HOME", m.home)
	t.Setenv("PATH", "/usr/bin:/bin")
	// A stand-in npm that empties its cache the way `npm cache clean` does.
	mk(t, filepath.Join(m.home, ".local", "bin", "npm"), 0)
	script := "#!/bin/sh\n[ \"$1 $2 $3\" = \"cache clean --force\" ] || exit 3\nrm -rf \"$HOME/.npm/_cacache/index\"\necho cleaned\n"
	npmBin := filepath.Join(m.home, ".local", "bin", "npm")
	if err := os.WriteFile(npmBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(npmBin, 0o755); err != nil {
		t.Fatal(err)
	}
	st := &memStore{}
	c := m.clutter(st)
	rep := c.Report(context.Background(), true)
	npm := byPath(t, rep, filepath.Join(m.home, ".npm", "_cacache"))
	if npm.Action != ActionClean || npm.Command != "npm cache clean --force" {
		t.Fatalf("npm item = %+v", npm)
	}
	res, err := c.Clean(context.Background(), "npm")
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes < 9000 || res.Output != "cleaned" {
		t.Fatalf("clean result = %+v", res)
	}
	if len(st.ledger) != 1 || st.ledger[0].Action != "clean:npm" || st.ledger[0].Bytes != res.Bytes {
		t.Fatalf("ledger = %+v", st.ledger)
	}
	if _, err := c.Clean(context.Background(), "yarn"); !errors.Is(err, ErrNotInInventory) {
		t.Fatalf("clean of an absent tool: %v", err)
	}
}

func TestLivePlacesPicksTheDeepestPlace(t *testing.T) {
	places := []Place{{Path: "/r"}, {Path: "/r/.worktrees/a"}}
	live := livePlaces(places, []model.WorkspaceActivity{
		{Workspace: "/r/.worktrees/a/pkg", Live: true},
		{Workspace: "/r/docs", Live: false},
		{Workspace: "/elsewhere", Live: true},
	})
	if !live["/r/.worktrees/a"] || live["/r"] || len(live) != 1 {
		t.Fatalf("live = %v", live)
	}
}

func TestTrashOnLinuxWritesTrashInfo(t *testing.T) {
	m := newMachine(t)
	t.Setenv("PATH", "/usr/bin:/bin")
	c := m.clutter(&memStore{})
	c.goos = "linux"
	target := filepath.Join(m.repo, ".tmp")
	res, err := c.Trash(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if res.TrashAt != filepath.Join(m.home, ".local", "share", "Trash", "files", ".tmp") {
		t.Fatalf("trash path = %s", res.TrashAt)
	}
	info, err := os.ReadFile(filepath.Join(m.home, ".local", "share", "Trash", "info", ".tmp.trashinfo"))
	if err != nil || !strings.Contains(string(info), "Path="+target+"\n") || !strings.HasPrefix(string(info), "[Trash Info]\n") {
		t.Fatalf("trashinfo = %q, %v", info, err)
	}
}
