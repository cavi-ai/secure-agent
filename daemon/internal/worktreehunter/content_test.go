package worktreehunter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const originMain = "refs/remotes/origin/main"

func TestClassifyKeepsMergeFactBesideOtherReasons(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	idle := facts{DefaultBranch: "origin/main", IndexTime: now.Add(-48 * time.Hour)}

	w := Worktree{Merged: mergedSquash, Changed: 1, Paths: []string{".mcp.json"}}
	classify(&w, idle, now, 14*24*time.Hour)
	if got := strings.Join(w.Reasons, " | "); w.State != StateKeep || got != "1 uncommitted change | merged into origin/main (squash)" {
		t.Errorf("squash-merged with an uncommitted change: state %s reasons %q", w.State, got)
	}

	w = Worktree{Merged: mergedAncestor, PreciousIgnored: []string{".env (17 B)"}}
	classify(&w, idle, now, 14*24*time.Hour)
	if got := strings.Join(w.Reasons, " | "); w.State != StateReview || got != "ignored files that only live here: .env (17 B) | contained in origin/main" {
		t.Errorf("merged with a precious file: state %s reasons %q", w.State, got)
	}

	w = Worktree{Merged: mergedContent, Unique: 3}
	classify(&w, idle, now, 14*24*time.Hour)
	if got := strings.Join(w.Reasons, " | "); w.State != StateRemove || got != "its changes are on origin/main (matched by content)" {
		t.Errorf("content-merged and idle: state %s reasons %q", w.State, got)
	}

	w = Worktree{Merged: mergedNo, Unique: 3, ContentLines: 5, ContentMissing: 2}
	classify(&w, idle, now, 14*24*time.Hour)
	want := "3 commits on no remote and not in origin/main (the branch keeps them after removal); 3 of 5 lines they add are on origin/main"
	if w.State != StateReview || len(w.Reasons) != 1 || w.Reasons[0] != want {
		t.Errorf("unmerged with a measure: state %s reasons %q, want %q", w.State, w.Reasons, want)
	}
}

// newMerged sets up a branch whose squash commit on main also carries a
// touch-up elsewhere in the same file, so no commit on main has the branch's
// patch id.
func squashWithTouchUp(t *testing.T, f fixture) string {
	t.Helper()
	wt := f.worktree(t, "touchup")
	commit(t, wt, "base.txt", "l1\nl2\nl3\nl4\nl5 branch\nl6\nl7\n", "branch edit")
	run(t, f.main, "merge", "-q", "--squash", "feat/touchup")
	write(t, filepath.Join(f.main, "base.txt"), "l1 main\nl2\nl3\nl4\nl5 branch\nl6\nl7\n")
	run(t, f.main, "add", "-A")
	run(t, f.main, "commit", "-q", "-m", "squash touchup, tidy l1")
	run(t, f.main, "push", "-q", "origin", "main")
	return wt
}

func TestContentMatchesSquashWithTouchUp(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()
	wt := squashWithTouchUp(t, f)

	// The patch-id check provably misses: the squash commit's diff has a
	// second hunk the branch's diff lacks.
	mb := run(t, wt, "merge-base", "HEAD", originMain)
	id, err := branchPatchID(ctx, wt, mb)
	if err != nil || id == "" {
		t.Fatalf("branch patch id = %q, %v", id, err)
	}
	ids, err := defaultPatchIDs(ctx, f.main, originMain)
	if err != nil || ids[id] {
		t.Fatalf("patch-id check must miss here: matched=%v err=%v", ids[id], err)
	}

	row, _, err := New(newMemStore(), home, Options{}).Inspect(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedContent || row.ContentLines != 1 || row.ContentMissing != 0 {
		t.Fatalf("merged=%q lines=%d missing=%d, want content 1 0", row.Merged, row.ContentLines, row.ContentMissing)
	}
}

// rewriteDefault replaces origin/main with a fresh, unrelated history holding
// files, as a repository recreated from scratch does.
func rewriteDefault(t *testing.T, f fixture, files map[string]string) {
	t.Helper()
	fresh := filepath.Join(f.root, "fresh")
	run(t, f.root, "init", "-q", "-b", "main", fresh)
	for name, content := range files {
		commit(t, fresh, name, content, "import "+name)
	}
	run(t, f.main, "fetch", "-q", fresh, "main")
	run(t, f.main, "update-ref", originMain, "FETCH_HEAD")
}

func TestContentAfterHistoryRewrite(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	wt := f.worktree(t, "arp")
	commit(t, wt, "apps/old-mcp/src/arp.mjs", "export const a = 1;\r\nexport const b = 2;\n", "arp")
	commit(t, wt, "apps/old-mcp/src/more.mjs", "export const c = 3;\n", "more")
	rewriteDefault(t, f, map[string]string{
		"apps/mcp/src/arp.mjs":  "export const a = 1;\nexport const b = 2;\n",
		"apps/mcp/src/more.mjs": "// moved\nexport const c = 3;\n",
	})
	if out, err := gitOK(ctx, wt, "merge-base", "HEAD", originMain); err != nil || out {
		t.Fatalf("the histories must share no commit: %v %v", out, err)
	}

	h := New(newMemStore(), home, Options{})
	row, _, err := h.Inspect(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedContent || row.ContentLines != 3 || row.ContentMissing != 0 {
		t.Fatalf("merged=%q lines=%d missing=%d, want content 3 0", row.Merged, row.ContentLines, row.ContentMissing)
	}

	// A line the rewritten history lacks is a measured "no".
	commit(t, wt, "apps/old-mcp/src/arp.mjs", "export const a = 1;\nexport const b = 2;\nexport const z = 26;\n", "extra")
	row, _, err = h.Inspect(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedNo || row.ContentLines != 4 || row.ContentMissing != 1 {
		t.Fatalf("merged=%q lines=%d missing=%d, want no 4 1", row.Merged, row.ContentLines, row.ContentMissing)
	}
}

func TestContentMeasuresMissingLines(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	wt := f.worktree(t, "notes")
	commit(t, wt, "notes.txt", "a\nb\nc\n", "notes")
	commit(t, f.main, "notes.txt", "a\nb\n", "main has two of them")
	run(t, f.main, "push", "-q", "origin", "main")

	row, _, err := New(newMemStore(), home, Options{}).Inspect(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedNo || row.ContentLines != 3 || row.ContentMissing != 1 {
		t.Fatalf("merged=%q lines=%d missing=%d, want no 3 1", row.Merged, row.ContentLines, row.ContentMissing)
	}
	want := "1 commit on no remote and not in origin/main (the branch keeps them after removal); 2 of 3 lines they add are on origin/main"
	if row.State != StateReview || len(row.Reasons) != 1 || row.Reasons[0] != want {
		t.Fatalf("state %s reasons %q, want review with %q", row.State, row.Reasons, want)
	}
}

func TestContentDeletedFileMustBeGoneFromMain(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	wt := f.worktree(t, "drop")
	if err := os.Remove(filepath.Join(wt, "base.txt")); err != nil {
		t.Fatal(err)
	}
	run(t, wt, "add", "-A")
	run(t, wt, "commit", "-q", "-m", "drop base")

	h := New(newMemStore(), home, Options{})
	row, _, err := h.Inspect(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedNo {
		t.Fatalf("main still has base.txt: merged=%q, want no", row.Merged)
	}

	// Main drops it too, in a commit whose patch id is not the branch's.
	if err := os.Remove(filepath.Join(f.main, "base.txt")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.main, "other.txt"), "other\n")
	run(t, f.main, "add", "-A")
	run(t, f.main, "commit", "-q", "-m", "drop base, add other")
	run(t, f.main, "push", "-q", "origin", "main")
	row, _, err = h.Inspect(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedContent {
		t.Fatalf("main dropped base.txt: merged=%q, want content", row.Merged)
	}
}

func TestContentUnknownWithoutABase(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	reflog := filepath.Join(strings.TrimSpace(run(t, f.main, "rev-parse", "--path-format=absolute", "--git-common-dir")), "logs", "refs", "heads")
	gone := f.worktree(t, "noreflog")
	commit(t, gone, "a.txt", "a\n", "a")
	expired := f.worktree(t, "expired")
	commit(t, expired, "b.txt", "b\n", "b")
	commit(t, expired, "c.txt", "c\n", "c")
	detached := filepath.Join(f.main, ".worktrees", "detached")
	run(t, f.main, "worktree", "add", "-q", "--detach", detached, "main")
	commit(t, detached, "d.txt", "d\n", "d")

	rewriteDefault(t, f, map[string]string{"a.txt": "a\n", "b.txt": "b\n", "c.txt": "c\n", "d.txt": "d\n"})

	// No reflog file at all.
	if err := os.Remove(filepath.Join(reflog, "feat", "noreflog")); err != nil {
		t.Fatal(err)
	}
	// A reflog whose creation entry expired starts mid-history: it must not
	// stand in for the fork point.
	path := filepath.Join(reflog, "feat", "expired")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	if len(lines) < 3 {
		t.Fatalf("reflog lines = %q", lines)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines[1:], "")), 0o644); err != nil {
		t.Fatal(err)
	}

	h := New(newMemStore(), home, Options{})
	for name, p := range map[string]string{"no reflog": gone, "expired reflog": expired, "detached HEAD": detached} {
		row, _, err := h.Inspect(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if row.Merged != mergedUnknown || row.ContentLines != 0 {
			t.Errorf("%s: merged=%q lines=%d, want unknown 0", name, row.Merged, row.ContentLines)
		}
	}
}

func TestContentUnknownOverFileBound(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "wide")
	for i := 0; i <= contentMaxFiles; i++ {
		write(t, filepath.Join(wt, "gen", fmt.Sprintf("f%03d.txt", i)), fmt.Sprintf("line %d\n", i))
	}
	run(t, wt, "add", "-A")
	run(t, wt, "commit", "-q", "-m", "many files")
	row, _, err := New(newMemStore(), home, Options{}).Inspect(context.Background(), wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedUnknown {
		t.Fatalf("%d files: merged=%q, want unknown", contentMaxFiles+1, row.Merged)
	}
}

func TestAdviceRequestOnSquashMergedBranch(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	commit(t, f.main, "docs/old.md", "old docs\n", "add old docs")
	run(t, f.main, "push", "-q", "origin", "main")
	wt := f.worktree(t, "adv")
	commit(t, wt, "docs/old.md", "old docs\nmore old docs\n", "extend old docs")
	commit(t, wt, "base.txt", "l1\nl2\nl3\nl4\nl5 branch\nl6\nl7\n", "branch edit")
	write(t, filepath.Join(wt, "scratch.txt"), "scratch\n")

	// A branch nobody merged, forked before main moved: its own edits are
	// not the default branch's, but the file main changed under it is.
	own := f.worktree(t, "own")
	commit(t, own, "docs/new.md", "new\n", "new doc")
	commit(t, own, "base.txt", "l1\nl2\nl3\nl4\nl5 own\nl6\nl7\n", "own edit")

	run(t, f.main, "merge", "-q", "--squash", "feat/adv")
	run(t, f.main, "commit", "-q", "-m", "squash adv")
	if err := os.Remove(filepath.Join(f.main, "docs", "old.md")); err != nil {
		t.Fatal(err)
	}
	run(t, f.main, "add", "-A")
	run(t, f.main, "commit", "-q", "-m", "drop the old docs")
	run(t, f.main, "push", "-q", "origin", "main")

	h := New(newMemStore(), home, Options{})
	req, err := h.AdviceRequest(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if req.Merged != mergedSquash || len(req.Commits) != 0 {
		t.Fatalf("merged=%q commits=%q, want squash and none", req.Merged, req.Commits)
	}
	if req.Behind != 2 {
		t.Errorf("behind = %d, want 2 (the squash and the drop)", req.Behind)
	}
	if got := strings.Join(req.MainStatus, "|"); got != "deleted on main: docs/old.md" {
		t.Errorf("main status = %q, want only the file main deleted", got)
	}
	if got := strings.Join(req.MainCommits, "|"); !strings.Contains(got, " drop the old docs") || !strings.Contains(got, " squash adv") {
		t.Errorf("main commits = %q", got)
	}
	if len(req.Paths) != 1 || req.Paths[0] != "scratch.txt" {
		t.Errorf("paths = %q", req.Paths)
	}

	req, err = h.AdviceRequest(ctx, own)
	if err != nil {
		t.Fatal(err)
	}
	if req.Merged != mergedNo || strings.Join(req.Commits, "|") != "own edit|new doc" {
		t.Errorf("unmerged: merged=%q commits=%q", req.Merged, req.Commits)
	}
	if got := strings.Join(req.MainStatus, "|"); got != "changed on main: base.txt" {
		t.Errorf("main status = %q, want only base.txt (docs/new.md is the branch's own file)", got)
	}
}

func TestMainStatusLinesAreBounded(t *testing.T) {
	var ns strings.Builder
	var differs []string
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&ns, "M\x00f%02d\x00", i)
		differs = append(differs, fmt.Sprintf("f%02d", i))
	}
	lines := mainStatusLines(ns.String(), differs)
	if len(lines) != maxMainStatus || lines[0] != "changed on main: f00" || lines[len(lines)-1] != "… and 6 more" {
		t.Fatalf("lines = %q", lines)
	}
	if got := mainStatusLines("D\x00gone\x00A\x00new\x00M\x00kept\x00", []string{"gone", "new"}); strings.Join(got, "|") != "deleted on main: gone|added on main: new" {
		t.Fatalf("filtered = %q", got)
	}
}
