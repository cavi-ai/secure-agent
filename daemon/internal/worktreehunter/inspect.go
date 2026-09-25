package worktreehunter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// listed is one entry of `git worktree list --porcelain`.
type listed struct {
	Path       string
	Head       string
	Branch     string // short name; "" when detached or bare
	Bare       bool
	Detached   bool
	Locked     bool
	LockReason string
	Prunable   bool
}

// listWorktrees runs `git worktree list --porcelain` in a repository. The
// first entry is the main worktree (or the bare repository).
func listWorktrees(ctx context.Context, dir string) ([]listed, error) {
	out, err := git(ctx, dir, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, err
	}
	return parseWorktreeList(out), nil
}

func parseWorktreeList(out string) []listed {
	var all []listed
	var cur *listed
	for _, line := range strings.Split(out, "\n") {
		key, val, _ := strings.Cut(line, " ")
		switch key {
		case "worktree":
			all = append(all, listed{Path: val})
			cur = &all[len(all)-1]
		case "HEAD":
			if cur != nil {
				cur.Head = val
			}
		case "branch":
			if cur != nil {
				cur.Branch = strings.TrimPrefix(val, "refs/heads/")
			}
		case "bare":
			if cur != nil {
				cur.Bare = true
			}
		case "detached":
			if cur != nil {
				cur.Detached = true
			}
		case "locked":
			if cur != nil {
				cur.Locked, cur.LockReason = true, val
			}
		case "prunable":
			if cur != nil {
				cur.Prunable = true
			}
		}
	}
	return all
}

// statusFacts is what `git status --porcelain=v2 --branch` says.
type statusFacts struct {
	Upstream     string
	Ahead        int
	Behind       int
	UpstreamGone bool
	Changed      int
	Untracked    int
	Conflicts    int
	Paths        []string // first maxPaths changed/untracked/conflicted paths
}

// maxPaths caps the paths a row carries: enough to say what is there.
const maxPaths = 20

func readStatus(ctx context.Context, dir string) (statusFacts, error) {
	out, err := git(ctx, dir, "status", "--porcelain=v2", "--branch", "--untracked-files=normal", "-z")
	if err != nil {
		return statusFacts{}, err
	}
	return parseStatus(out), nil
}

func parseStatus(out string) statusFacts {
	var s statusFacts
	hasAB := false
	fields := strings.Split(out, "\x00")
	addPath := func(p string) {
		if len(s.Paths) < maxPaths {
			s.Paths = append(s.Paths, p)
		}
	}
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasPrefix(f, "# branch.upstream "):
			s.Upstream = strings.TrimPrefix(f, "# branch.upstream ")
		case strings.HasPrefix(f, "# branch.ab "):
			hasAB = true
			for _, n := range strings.Fields(strings.TrimPrefix(f, "# branch.ab ")) {
				v, _ := strconv.Atoi(n[1:])
				if n[0] == '+' {
					s.Ahead = v
				} else {
					s.Behind = v
				}
			}
		case strings.HasPrefix(f, "1 "):
			if p := strings.SplitN(f, " ", 9); len(p) == 9 {
				s.Changed++
				addPath(p[8])
			}
		case strings.HasPrefix(f, "2 "):
			if p := strings.SplitN(f, " ", 10); len(p) == 10 {
				s.Changed++
				addPath(p[9])
			}
			i++ // the rename's original path is the next field
		case strings.HasPrefix(f, "u "):
			if p := strings.SplitN(f, " ", 11); len(p) == 11 {
				s.Conflicts++
				addPath(p[10])
			}
		case strings.HasPrefix(f, "? "):
			s.Untracked++
			addPath(strings.TrimPrefix(f, "? "))
		}
	}
	// porcelain v2 omits branch.ab when the upstream ref no longer exists.
	s.UpstreamGone = s.Upstream != "" && !hasAB
	return s
}

// preciousDirs and preciousFiles mark ignored entries that are usually the
// only copy of something: local secrets, agent state, scratch evidence.
// Build outputs and dependency trees are regenerable and never block.
var (
	preciousDirs  = map[string]bool{".tmp": true, ".claude": true, ".remember": true}
	preciousFiles = []string{".env", ".env.*", "*.pem", "*.key"}
)

// junkFiles never count as content: a directory holding only these is empty.
var junkFiles = map[string]bool{".DS_Store": true}

// maxIgnored caps how many ignored entries one worktree is read for.
const maxIgnored = 5000

// maxWalk caps the files counted under one precious directory.
const maxWalk = 20000

// ignoredFacts lists precious ignored entries and counts the rest.
type ignoredFacts struct {
	Precious []string
	Other    int
}

// readIgnored lists ignored entries (untracked directories collapsed, empty
// ones skipped) and describes each precious one with its size, dropping a
// precious directory that holds nothing but junk.
func readIgnored(ctx context.Context, dir string) (ignoredFacts, error) {
	out, err := git(ctx, dir, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "--no-empty-directory", "-z")
	if err != nil {
		return ignoredFacts{}, err
	}
	f := classifyIgnored(strings.Split(out, "\x00"))
	described := f.Precious[:0]
	for _, e := range f.Precious {
		if d, ok := describeEntry(dir, e); ok {
			described = append(described, d)
		}
	}
	f.Precious = described
	return f, nil
}

// describeEntry renders a precious entry with what it holds: "<dir>/ (N
// files, 1.2 MB)" or "<file> (340 B)". ok is false for a directory with no
// files besides junk.
func describeEntry(root, entry string) (string, bool) {
	p := filepath.Join(root, entry)
	if !strings.HasSuffix(entry, "/") {
		st, err := os.Lstat(p)
		if err != nil {
			return entry, true
		}
		return fmt.Sprintf("%s (%s)", entry, humanBytes(st.Size())), true
	}
	files, bytes, capped := 0, int64(0), false
	_ = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || junkFiles[d.Name()] {
			return nil
		}
		if files == maxWalk {
			capped = true
			return filepath.SkipAll
		}
		files++
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			bytes += info.Size()
		}
		return nil
	})
	if files == 0 {
		return "", false
	}
	count := plural(files, "file", "files")
	if capped {
		count = fmt.Sprintf("%d+ files", files)
	}
	return fmt.Sprintf("%s (%s, %s)", entry, count, humanBytes(bytes)), true
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func classifyIgnored(entries []string) ignoredFacts {
	var f ignoredFacts
	for i, e := range entries {
		if i >= maxIgnored {
			break
		}
		if e == "" {
			continue
		}
		if isPrecious(e) {
			if len(f.Precious) < maxPaths {
				f.Precious = append(f.Precious, e)
			}
			continue
		}
		f.Other++
	}
	return f
}

func isPrecious(entry string) bool {
	trimmed := strings.TrimSuffix(entry, "/")
	if junkFiles[filepath.Base(trimmed)] {
		return false
	}
	for _, part := range strings.Split(trimmed, "/") {
		if preciousDirs[part] {
			return true
		}
	}
	base := filepath.Base(trimmed)
	for _, pat := range preciousFiles {
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
	}
	return false
}

// headTime is HEAD's committer time.
func headTime(ctx context.Context, dir string) time.Time {
	out, err := git(ctx, dir, "log", "-1", "--format=%ct", "HEAD")
	if err != nil {
		return time.Time{}
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// indexTime is the mtime of the worktree's index: every agent `git add` or
// `git status` refreshes it, so it tracks work that has no commit yet.
func indexTime(dir string) time.Time {
	st, err := os.Stat(filepath.Join(adminDir(dir), "index"))
	if err != nil {
		return time.Time{}
	}
	return st.ModTime().UTC()
}

// adminDir is the worktree's own git dir: the target of its .git file, or
// <dir>/.git.
func adminDir(dir string) string {
	gitdir := filepath.Join(dir, ".git")
	if data, err := os.ReadFile(gitdir); err == nil {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:"); ok {
			gitdir = strings.TrimSpace(rest)
			if !filepath.IsAbs(gitdir) {
				gitdir = filepath.Join(dir, gitdir)
			}
		}
	}
	return gitdir
}

// submoduleFacts are the worktree's populated submodules and the work
// that lives only in their git dirs, which sit under the worktree's own
// git dir (modules/) and go with it on removal.
type submoduleFacts struct {
	Populated int
	Local     []string
}

// readSubmodules lists populated submodules (recursively) and, for each,
// commits on its branches or HEAD that no remote has, and a stash.
func readSubmodules(ctx context.Context, dir string) (submoduleFacts, error) {
	var s submoduleFacts
	_, errMods := os.Stat(filepath.Join(dir, ".gitmodules"))
	_, errDir := os.Stat(filepath.Join(adminDir(dir), "modules"))
	if errMods != nil && errDir != nil {
		return s, nil
	}
	out, err := git(ctx, dir, "submodule", "status", "--recursive")
	if err != nil {
		return s, err
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 || line[0] == '-' {
			continue
		}
		fields := strings.Fields(line[1:])
		if len(fields) < 2 {
			continue
		}
		path := fields[1]
		sub := filepath.Join(dir, path)
		s.Populated++
		n, err := countCommits(ctx, sub, "--branches", "HEAD", "--not", "--remotes")
		if err != nil {
			return s, err
		}
		if n > 0 {
			s.Local = append(s.Local, fmt.Sprintf("submodule %s has %s on no remote (removal loses them)", path, plural(n, "commit", "commits")))
		}
		if ok, err := gitOK(ctx, sub, "rev-parse", "--quiet", "--verify", "refs/stash"); err != nil {
			return s, err
		} else if ok {
			s.Local = append(s.Local, "submodule "+path+" has a stash (removal loses it)")
		}
	}
	return s, nil
}

// countCommits runs `git rev-list --count <args>`.
func countCommits(ctx context.Context, dir string, args ...string) (int, error) {
	out, err := git(ctx, dir, append([]string{"rev-list", "--count"}, args...)...)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

// defaultBranch picks the ref a merge is measured against: origin/HEAD's
// target, else the first of origin/main, origin/master, main, master.
func defaultBranch(ctx context.Context, dir string) string {
	if out, err := git(ctx, dir, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"); err == nil {
		if ref := strings.TrimSpace(out); ref != "" {
			return ref
		}
	}
	candidates := []string{"refs/remotes/origin/main", "refs/remotes/origin/master", "refs/heads/main", "refs/heads/master"}
	out, err := git(ctx, dir, append([]string{"for-each-ref", "--format=%(refname)"}, candidates...)...)
	if err != nil {
		return ""
	}
	have := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		have[strings.TrimSpace(l)] = true
	}
	for _, c := range candidates {
		if have[c] {
			return c
		}
	}
	return ""
}

// shortRef drops refs/heads/ and refs/remotes/ for display.
func shortRef(ref string) string {
	if s, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return s
	}
	return strings.TrimPrefix(ref, "refs/remotes/")
}

// branchStashes counts stash entries per branch from `git stash list`.
func branchStashes(ctx context.Context, dir string) map[string]int {
	out, err := git(ctx, dir, "stash", "list", "--format=%gs")
	if err != nil {
		return nil
	}
	// Subjects read "WIP on <branch>: <sha> <msg>" or "On <branch>: <msg>".
	counts := map[string]int{}
	for _, l := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(l, "WIP on ")
		if !ok {
			rest, ok = strings.CutPrefix(l, "On ")
		}
		if !ok {
			continue
		}
		if b, _, ok := strings.Cut(rest, ":"); ok {
			counts[b]++
		}
	}
	return counts
}

// Merge verdicts.
const (
	mergedAncestor = "ancestor" // HEAD is reachable from the default branch
	mergedSquash   = "squash"   // the branch's combined diff landed as one commit
	mergedEmpty    = "empty"    // the branch's tree equals its merge-base: nothing to merge
	mergedNo       = "no"
	mergedUnknown  = "unknown" // too far behind to check, or a git error
)

// squashDepth is how many recent non-merge commits of the default branch
// are fingerprinted for the squash check. A branch whose merge-base is
// further back than this is reported unknown, never guessed.
const squashDepth = 1000

// squashTimeout bounds the one `log -p | patch-id` pass per repository.
const squashTimeout = 90 * time.Second

// Both sides of the squash check diff with zero context lines (-U0): a
// squash commit lands on a default branch that moved since the branch
// forked, so its context lines differ from the branch's own diff wherever
// both touched nearby lines. patch-id ignores line numbers; without context
// only the changed lines themselves are compared.

// defaultPatchIDs fingerprints the newest squashDepth non-merge commits of
// the default branch.
func defaultPatchIDs(ctx context.Context, dir, def string) (map[string]bool, error) {
	ids, err := patchIDs(ctx, dir, squashTimeout,
		"log", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-merges", "-n", strconv.Itoa(squashDepth), def)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

// branchPatchID fingerprints the branch as one combined diff from its
// merge-base with the default branch: the shape of a squash-merge commit.
// Empty when the branch changes nothing.
func branchPatchID(ctx context.Context, dir, mergeBase string) (string, error) {
	ids, err := patchIDs(ctx, dir, gitTimeout, "diff", "-U0", "--no-color", "--no-ext-diff", mergeBase, "HEAD")
	if err != nil || len(ids) == 0 {
		return "", err
	}
	return ids[0], nil
}
