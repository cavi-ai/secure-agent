package worktreehunter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

	w = Worktree{Merged: contentSimilar, Unique: 3}
	classify(&w, idle, now, 14*24*time.Hour)
	if got := strings.Join(w.Reasons, " | "); w.State != StateReview || got != "3 commits on no remote and not in origin/main (the branch keeps them after removal)" {
		t.Errorf("content similarity and idle: state %s reasons %q", w.State, got)
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
	if row.Merged != contentSimilar || row.ContentLines != 1 || row.ContentMissing != 0 {
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
	if row.Merged != contentSimilar || row.ContentLines != 3 || row.ContentMissing != 0 || !row.Unrelated {
		t.Fatalf("merged=%q lines=%d missing=%d unrelated=%v, want content 3 0 true", row.Merged, row.ContentLines, row.ContentMissing, row.Unrelated)
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
	// The old history's commit count says nothing about the branch's own
	// work; the reason measures what it added since it was created.
	want := "shares no history with origin/main (rewritten); 3 of 4 lines it added since it was created are on origin/main; the branch keeps its commits after removal"
	if row.State != StateReview || !slices.Contains(row.Reasons, want) {
		t.Fatalf("state %s reasons %q, want review with %q", row.State, row.Reasons, want)
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
	if row.Merged != contentSimilar {
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
		if row.Merged != mergedUnknown || row.ContentLines != 0 || !row.Unrelated {
			t.Errorf("%s: merged=%q lines=%d unrelated=%v, want unknown 0 true", name, row.Merged, row.ContentLines, row.Unrelated)
		}
	}
}

// A diff over the content check's bounds is not measured; with a merge-base
// the squash check already answered no, and that answer stands.
func TestContentOverFileBoundKeepsSquashAnswer(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "wide")
	for i := 0; i <= contentMaxFiles; i++ {
		write(t, filepath.Join(wt, "gen", fmt.Sprintf("f%04d.txt", i)), fmt.Sprintf("line %d\n", i))
	}
	run(t, wt, "add", "-A")
	run(t, wt, "commit", "-q", "-m", "many files")
	row, _, err := New(newMemStore(), home, Options{}).Inspect(context.Background(), wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedNo || row.ContentLines != 0 {
		t.Fatalf("%d files: merged=%q lines=%d, want no, unmeasured", contentMaxFiles+1, row.Merged, row.ContentLines)
	}
}

// Reading more counterpart content than the bound allows is unknown, never
// a partial answer.
func TestContentUnknownOverReadBound(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "big")
	commit(t, wt, "big.txt", "the branch line\n", "big")
	rewriteDefault(t, f, map[string]string{"big.txt": "the branch line\n" + strings.Repeat("filler line\n", 20)})
	old := contentMaxReadBytes
	contentMaxReadBytes = 64
	defer func() { contentMaxReadBytes = old }()
	row, _, err := New(newMemStore(), home, Options{}).Inspect(context.Background(), wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedUnknown || row.ContentLines != 0 {
		t.Fatalf("merged=%q lines=%d, want unknown, unmeasured", row.Merged, row.ContentLines)
	}
}

// A line the default branch has only in a longer form (a list it appended
// to) still carries the branch's work; a short line never matches that way,
// and too many such lines are a rewrite, not an extension.
func TestContentExtendedLines(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	ext := f.worktree(t, "ext")
	commit(t, ext, "reg.py", "alpha_one = 1\nbeta_two = 2\nguarded = alpha_one or beta_two\n", "reg")
	short := f.worktree(t, "short")
	commit(t, short, "short.py", "x = y\n", "short")
	many := f.worktree(t, "many")
	commit(t, many, "many.py", "a1 = b1 or c1\na2 = b2 or c2\na3 = b3 or c3\na4 = b4 or c4\na5 = b5 or c5\n", "many")
	rewriteDefault(t, f, map[string]string{
		"reg.py":   "alpha_one = 1\nbeta_two = 2\ngamma_three = 3\nguarded = alpha_one or beta_two or gamma_three\n",
		"short.py": "x = y + z\n",
		"many.py":  "a1 = b1 or c1 or d1\na2 = b2 or c2 or d2\na3 = b3 or c3 or d3\na4 = b4 or c4 or d4\na5 = b5 or c5 or d5\n",
	})

	h := New(newMemStore(), home, Options{})
	row, _, err := h.Inspect(ctx, ext)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != contentSimilar || row.ContentLines != 3 || row.ContentMissing != 0 || row.ContentExtended != 1 {
		t.Fatalf("ext: merged=%q lines=%d missing=%d extended=%d, want content 3 0 1", row.Merged, row.ContentLines, row.ContentMissing, row.ContentExtended)
	}
	want := "shares no history with origin/main (rewritten); 3 of 3 lines it added since it was created are on origin/main (1 line only in a longer form); the branch keeps its commits after removal"
	if !slices.Contains(row.Reasons, want) {
		t.Fatalf("ext reasons %q, want %q", row.Reasons, want)
	}

	row, _, err = h.Inspect(ctx, short)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedNo || row.ContentMissing != 1 || row.ContentExtended != 0 {
		t.Fatalf("short: merged=%q missing=%d extended=%d, want no 1 0", row.Merged, row.ContentMissing, row.ContentExtended)
	}

	row, _, err = h.Inspect(ctx, many)
	if err != nil {
		t.Fatal(err)
	}
	if row.Merged != mergedNo || row.ContentMissing != 0 || row.ContentExtended != 5 {
		t.Fatalf("many: merged=%q missing=%d extended=%d, want no 0 5", row.Merged, row.ContentMissing, row.ContentExtended)
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

// inspectRow is Inspect with a fresh hunter.
func inspectRow(t *testing.T, home, wt string) Worktree {
	t.Helper()
	row, _, err := New(newMemStore(), home, Options{}).Inspect(context.Background(), wt)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// moveMainOn commits an unrelated file on main and pushes, so neither
// ancestry nor a patch id says a branch is merged.
func moveMainOn(t *testing.T, f fixture) {
	t.Helper()
	commit(t, f.main, "other.txt", "other\n", "other")
	run(t, f.main, "push", "-q", "origin", "main")
}

// What a branch removes or flips must be gone from main too: a branch that
// only deletes lines, or flips a value to one that exists elsewhere in the
// file, is not merged while main still has the old line.
func TestContentRemovalsMustLand(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	commit(t, f.main, "cfg.yml", "a:\n  enabled: false\nb:\n  enabled: true\n", "cfg")
	run(t, f.main, "push", "-q", "origin", "main")
	del := f.worktree(t, "del")
	commit(t, del, "base.txt", "l1\nl2\nl5\nl6\nl7\n", "delete l3 l4")
	flip := f.worktree(t, "flip")
	commit(t, flip, "cfg.yml", "a:\n  enabled: true\nb:\n  enabled: true\n", "enable a")
	moveMainOn(t, f)

	row := inspectRow(t, home, del)
	if row.Merged != mergedNo || row.ContentLines != 0 || row.ContentOther != 2 {
		t.Fatalf("deletion: merged=%q lines=%d other=%d, want no 0 2", row.Merged, row.ContentLines, row.ContentOther)
	}
	want := "1 commit on no remote and not in origin/main (the branch keeps them after removal); 2 lines or files it removes or changes still differ on origin/main"
	if !slices.Contains(row.Reasons, want) {
		t.Fatalf("deletion reasons %q, want %q", row.Reasons, want)
	}
	if row = inspectRow(t, home, flip); row.Merged != mergedNo || row.ContentOther != 1 {
		t.Fatalf("flip: merged=%q other=%d, want no 1", row.Merged, row.ContentOther)
	}

	// Once main makes the same removal, the branch is merged by content.
	commit(t, f.main, "base.txt", "l1\nl2\nl5\nl6\nl7\nl8\n", "drop l3 l4, add l8")
	run(t, f.main, "push", "-q", "origin", "main")
	if row = inspectRow(t, home, del); row.Merged != contentSimilar || row.ContentOther != 0 {
		t.Fatalf("landed deletion: merged=%q other=%d, want content 0", row.Merged, row.ContentOther)
	}
}

// A mode change is merged only when main's file has the same mode.
func TestContentModeChangeMustMatch(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "mode")
	if err := os.Chmod(filepath.Join(wt, "base.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, wt, "commit", "-q", "-am", "chmod +x")
	moveMainOn(t, f)
	if row := inspectRow(t, home, wt); row.Merged != mergedNo || row.ContentOther != 1 {
		t.Fatalf("mode only: merged=%q other=%d, want no 1", row.Merged, row.ContentOther)
	}

	// Main takes the mode change inside a bigger commit: no patch id
	// matches, the content check does.
	if err := os.Chmod(filepath.Join(f.main, "base.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.main, "other.txt"), "other, edited\n")
	run(t, f.main, "commit", "-q", "-am", "chmod and more")
	run(t, f.main, "push", "-q", "origin", "main")
	if row := inspectRow(t, home, wt); row.Merged != contentSimilar {
		t.Fatalf("mode on main: merged=%q, want content", row.Merged)
	}
}

// The line a branch shortened or rewrote is still on main in its original,
// longer form; that is the branch's own pre-image, never an extension.
func TestContentPreImageIsNotALongerForm(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	commit(t, f.main, "calc.txt", "total = price + tax + shipping\nprint(total)\n", "calc")
	commit(t, f.main, "gate.go", "func ok() bool {\n\tif count > limit && enabled {\n\t\treturn true\n\t}\n\treturn false\n}\n", "gate")
	run(t, f.main, "push", "-q", "origin", "main")
	short := f.worktree(t, "short")
	commit(t, short, "calc.txt", "total = price + tax\nprint(total)\n", "drop shipping")
	flip := f.worktree(t, "flip")
	commit(t, flip, "gate.go", "func ok() bool {\n\tif count < limit {\n\t\treturn true\n\t}\n\treturn false\n}\n", "fix comparison")
	moveMainOn(t, f)
	for name, wt := range map[string]string{"shortened": short, "operator flip": flip} {
		if row := inspectRow(t, home, wt); row.Merged != mergedNo || row.ContentExtended != 0 || row.ContentMissing != 1 {
			t.Errorf("%s: merged=%q missing=%d extended=%d, want no 1 0", name, row.Merged, row.ContentMissing, row.ContentExtended)
		}
	}
}

// A line added many times needs as many copies on main: one existing copy
// does not stand in for fifty.
func TestContentCountsCopies(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "dup")
	commit(t, wt, "base.txt", "l1\nl2\nl3\nl4\nl5\nl6\nl7\n"+strings.Repeat("l7\n", 50), "dup")
	moveMainOn(t, f)
	if row := inspectRow(t, home, wt); row.Merged != mergedNo || row.ContentLines != 50 || row.ContentMissing != 49 {
		t.Fatalf("merged=%q lines=%d missing=%d, want no 50 49", row.Merged, row.ContentLines, row.ContentMissing)
	}
}

// A new file stands in for nothing on main just because some other
// directory has a file of the same name.
func TestContentBasenameNeedsADirectory(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "gi")
	commit(t, wt, "docs/.gitignore", ".env\nnode_modules/\n", "docs gitignore")
	moveMainOn(t, f)
	if row := inspectRow(t, home, wt); row.Merged != mergedNo || row.ContentMissing != 2 {
		t.Fatalf("merged=%q missing=%d, want no 2", row.Merged, row.ContentMissing)
	}
}

// After a history rewrite only the branch's own commits are measured; a
// branch created from another unmerged branch says exactly that.
func TestContentRewrittenHistoryNamesWhatWasMeasured(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	a := f.worktree(t, "A")
	commit(t, a, "a.txt", "parent unmerged work\n", "A work")
	b := filepath.Join(f.main, ".worktrees", "B")
	run(t, f.main, "worktree", "add", "-q", "-b", "feat/B", b, "feat/A")
	commit(t, b, "b.txt", "child work\n", "B work")
	rewriteDefault(t, f, map[string]string{"b.txt": "child work\n"})
	row := inspectRow(t, home, b)
	want := "shares no history with origin/main (rewritten); 1 of 1 lines it added since it was created are on origin/main; the branch keeps its commits after removal"
	if row.Merged != contentSimilar || len(row.Reasons) == 0 || !strings.HasPrefix(row.Reasons[len(row.Reasons)-1], want) {
		t.Fatalf("merged=%q reasons=%q, want content with %q", row.Merged, row.Reasons, want)
	}

	// The advisor gets no "commits since the fork" for a base main never had.
	req, err := New(newMemStore(), home, Options{}).AdviceRequest(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if req.Behind != 0 || len(req.MainCommits) != 0 {
		t.Fatalf("behind=%d mainCommits=%q, want none for an unrelated base", req.Behind, req.MainCommits)
	}
}

// The longer-form search has a work bound; past it, lines stay missing.
func TestContentLongerFormWorkBound(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "ext")
	commit(t, wt, "reg.py", "alpha_one = 1\nbeta_two = 2\nguarded = alpha_one or beta_two\n", "reg")
	rewriteDefault(t, f, map[string]string{"reg.py": "alpha_one = 1\nbeta_two = 2\nguarded = alpha_one or beta_two or gamma\n"})
	old := extendedMaxWork
	extendedMaxWork = 1
	defer func() { extendedMaxWork = old }()
	if row := inspectRow(t, home, wt); row.Merged != mergedNo || row.ContentMissing != 1 || row.ContentExtended != 0 {
		t.Fatalf("merged=%q missing=%d extended=%d, want no 1 0", row.Merged, row.ContentMissing, row.ContentExtended)
	}
}

// A cancelled check stops inside the longer-form search.
func TestLongerFormHonorsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lc := countLines([]byte(strings.Repeat("unrelated words here\n", 5000)))
	work := 4095
	if _, err := longerFormIn(ctx, miss{line: "alpha beta gamma", n: 1, in: []*lineCounts{&lc}}, &work); err == nil {
		t.Fatal("cancelled search returned no error")
	}
}

// A partial clone never fetches a missing object while the hunter reads it.
func TestGitNeverLazyFetches(t *testing.T) {
	isolateGit(t)
	f := newFixture(t)
	run(t, f.origin, "config", "uploadpack.allowFilter", "true")
	clone := filepath.Join(f.root, "partial")
	run(t, f.root, "clone", "-q", "--no-checkout", "--filter=blob:none", "file://"+f.origin, clone)
	blob := strings.TrimSpace(run(t, f.main, "rev-parse", "main:base.txt"))
	if err := gitCommand(context.Background(), clone, "cat-file", "-e", blob).Run(); err == nil {
		t.Fatal("the hunter read a blob the partial clone does not have")
	}
	out := runEnv(t, []string{"GIT_NO_LAZY_FETCH=1"}, clone, "cat-file", "--batch-check=%(objectname)", "--batch-all-objects")
	if strings.Contains(out, blob) {
		t.Fatalf("the hunter's read fetched %s into the clone", blob)
	}
}
