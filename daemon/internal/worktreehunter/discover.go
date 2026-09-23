package worktreehunter

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// globalDirs are home-relative globs where agent apps keep worktrees outside
// the repository. Each match is a worktree whose .git file names its repo.
// A missing directory costs one failed stat.
var globalDirs = []string{
	".codex/worktrees/*/*",     // Codex app: <hash>/<repo>
	".cursor/worktrees/*/*",    // Cursor: <repo>/<id>
	".claude/worktrees/*",      // Claude Code (home-level)
	"conductor/workspaces/*/*", // Conductor: <repo>/<name>
}

// repoContainers are repo-relative directories agents create worktrees in.
var repoContainers = []string{
	".worktrees",
	"worktrees",
	".claude/worktrees",
	".claude/.worktrees",
	".codex/worktrees",
	".cursor/worktrees",
}

// rootScanDepth bounds the walk under a configured scan root.
const rootScanDepth = 3

// repoRef identifies one repository by its common git directory.
type repoRef struct {
	// Common is the shared git dir (<main>/.git, or the bare repo dir).
	Common string
	// Main is the main worktree, or the bare repo dir.
	Main string
	Bare bool
}

// orphanDir is a directory that claims to be a worktree (its .git file
// names an admin entry) while git no longer knows it: the entry is gone, so
// `git worktree` cannot remove it and its files are the only copy.
type orphanDir struct {
	Path string
	// Main is the repository the dead gitdir pointed into, when the path
	// has the <main>/.git/worktrees/<name> shape.
	Main string
}

// resolveRepo walks up from dir to the nearest .git entry, the way git
// does, and names the repository it belongs to. A .git file whose gitdir no
// longer exists yields an orphan instead.
func resolveRepo(dir string) (ref repoRef, orphan *orphanDir, ok bool) {
	dir = filepath.Clean(dir)
	for {
		dotGit := filepath.Join(dir, ".git")
		st, err := os.Lstat(dotGit)
		if err == nil {
			if st.IsDir() {
				return repoRef{Common: canonical(dotGit), Main: canonical(dir)}, nil, true
			}
			return resolveGitFile(dir, dotGit)
		}
		if isBareRepo(dir) {
			c := canonical(dir)
			return repoRef{Common: c, Main: c, Bare: true}, nil, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return repoRef{}, nil, false
		}
		dir = parent
	}
}

// resolveGitFile follows a worktree's (or submodule's) .git file.
func resolveGitFile(dir, dotGit string) (repoRef, *orphanDir, bool) {
	data, err := os.ReadFile(dotGit)
	if err != nil {
		return repoRef{}, nil, false
	}
	gitdir, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
	if !ok {
		return repoRef{}, nil, false
	}
	gitdir = strings.TrimSpace(gitdir)
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(dir, gitdir)
	}
	if _, err := os.Stat(gitdir); err != nil {
		return repoRef{}, &orphanDir{Path: canonical(dir), Main: mainFromAdminDir(gitdir)}, false
	}
	common := gitdir
	if c, err := os.ReadFile(filepath.Join(gitdir, "commondir")); err == nil {
		common = strings.TrimSpace(string(c))
		if !filepath.IsAbs(common) {
			common = filepath.Join(gitdir, common)
		}
	}
	common = canonical(common)
	if filepath.Base(common) == ".git" {
		return repoRef{Common: common, Main: filepath.Dir(common)}, nil, true
	}
	// A submodule (.git/modules/<name>) or a worktree of a bare repo.
	return repoRef{Common: common, Main: common, Bare: true}, nil, true
}

// mainFromAdminDir maps <main>/.git/worktrees/<name> to <main>.
func mainFromAdminDir(gitdir string) string {
	gitdir = filepath.Clean(gitdir)
	wt := filepath.Dir(gitdir)
	if filepath.Base(wt) != "worktrees" || filepath.Base(filepath.Dir(wt)) != ".git" {
		return ""
	}
	return canonical(filepath.Dir(filepath.Dir(wt)))
}

// isBareRepo reports whether dir itself is a bare repository (HEAD, objects
// and refs at its top level, named *.git). A checkout's own .git directory
// is not one: the walk continues to the checkout above it.
func isBareRepo(dir string) bool {
	if filepath.Base(dir) == ".git" {
		return false
	}
	for _, name := range []string{"HEAD", "objects", "refs"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return filepath.Ext(dir) == ".git"
}

// canonical resolves symlinks so the same repo found through /var and
// /private/var dedupes; a path that no longer resolves stays as given.
func canonical(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// found is one repository the discovery pass turned up.
type found struct {
	Ref    repoRef
	Source string
}

// discovery is the result of one discovery pass.
type discovery struct {
	Repos   []found
	Orphans []orphanDir
}

// discoverInput is everything discovery reads besides the filesystem.
type discoverInput struct {
	Home       string
	Roots      []string
	Saved      []model.WorktreeRepo
	Workspaces []model.WorkspaceActivity
}

// discover turns every seed into a repository: saved repos, agent session
// workspaces, the global agent worktree directories and configured scan
// roots; then each repo's worktree containers, which can name further repos
// and orphans. Hidden saved repos are dropped wherever they are found.
func discover(ctx context.Context, in discoverInput) discovery {
	var d discovery
	seen := map[string]int{} // common dir -> index in d.Repos
	hidden := map[string]bool{}
	orphanSeen := map[string]bool{}
	add := func(dir, source string) {
		ref, orphan, ok := resolveRepo(dir)
		if orphan != nil && !orphanSeen[orphan.Path] {
			orphanSeen[orphan.Path] = true
			d.Orphans = append(d.Orphans, *orphan)
		}
		if !ok || hidden[ref.Main] {
			return
		}
		if _, dup := seen[ref.Common]; dup {
			return
		}
		seen[ref.Common] = len(d.Repos)
		d.Repos = append(d.Repos, found{Ref: ref, Source: source})
	}

	for _, r := range in.Saved {
		if r.Hidden {
			hidden[canonical(r.Path)] = true
		}
	}
	for _, r := range in.Saved {
		if !r.Hidden {
			add(r.Path, r.Source)
		}
	}
	for _, w := range in.Workspaces {
		if ctx.Err() != nil {
			return d
		}
		add(w.Workspace, model.RepoSourceSession)
	}
	if in.Home != "" {
		for _, pattern := range globalDirs {
			matches, _ := filepath.Glob(filepath.Join(in.Home, pattern))
			for _, m := range matches {
				add(m, model.RepoSourceScan)
			}
		}
	}
	for _, root := range in.Roots {
		for _, repo := range walkRoot(ctx, root, rootScanDepth) {
			add(repo, model.RepoSourceRoot)
		}
	}
	// Containers of every repo found so far; a container can hold worktrees
	// of other repositories and orphans. One level: repos found here do not
	// get their containers scanned again in this pass.
	for _, f := range append([]found(nil), d.Repos...) {
		if f.Ref.Bare {
			continue
		}
		for _, c := range repoContainers {
			matches, _ := filepath.Glob(filepath.Join(f.Ref.Main, c, "*"))
			for _, m := range matches {
				if st, err := os.Stat(m); err == nil && st.IsDir() {
					add(m, model.RepoSourceScan)
				}
			}
		}
	}
	return d
}

// walkRoot finds repositories under root down to depth levels, without
// descending into a repository or into node_modules/vendor trees.
func walkRoot(ctx context.Context, root string, depth int) []string {
	var out []string
	var walk func(dir string, level int)
	walk = func(dir string, level int) {
		if ctx.Err() != nil {
			return
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			out = append(out, dir)
			return
		}
		if level == depth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" {
				continue
			}
			walk(filepath.Join(dir, name), level+1)
		}
	}
	walk(filepath.Clean(root), 0)
	return out
}
