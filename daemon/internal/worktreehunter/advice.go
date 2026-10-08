package worktreehunter

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// ErrNothingToAdvise is returned for a worktree whose directory is gone.
var ErrNothingToAdvise = errors.New("the worktree's directory is gone; prune it instead")

// maxAdviceCommits bounds the commit subjects sent to the advisor.
const maxAdviceCommits = 10

// AdviceRequest inspects path now and returns what the local advisor needs
// for a note: the fresh verdict, its paths and precious files, and the
// subjects of commits that are on no remote and not in the default branch.
func (h *Hunter) AdviceRequest(ctx context.Context, path string) (model.WorktreeAdviceRequest, error) {
	if !filepath.IsAbs(path) {
		return model.WorktreeAdviceRequest{}, errors.New("path must be absolute")
	}
	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	rs, l, err := h.locate(ctx, path)
	if err != nil {
		return model.WorktreeAdviceRequest{}, err
	}
	row := h.judge(ctx, rs, l)
	if row.State == StatePrune {
		return model.WorktreeAdviceRequest{}, ErrNothingToAdvise
	}
	req := model.WorktreeAdviceRequest{
		Path: row.Path, Head: row.Head, Branch: orDetached(row.Branch), State: row.State,
		IdleDays: row.IdleDays, Reasons: row.Reasons, Paths: row.Paths, Precious: row.PreciousIgnored,
		Merged: row.Merged,
	}
	if rs.def != "" {
		mainSide(ctx, l.Path, l.Branch, rs.def, &req)
	}
	if row.Unique > 0 && !isMerged(row.Merged) {
		args := []string{"log", "--format=%s", "-n", strconv.Itoa(maxAdviceCommits), "HEAD", "--not", "--remotes"}
		if rs.def != "" {
			args = append(args, rs.def)
		}
		if out, err := git(ctx, l.Path, args...); err == nil {
			for _, s := range strings.Split(strings.TrimSpace(out), "\n") {
				if s != "" && len(req.Commits) < maxAdviceCommits {
					req.Commits = append(req.Commits, s)
				}
			}
		}
	}
	return req, nil
}

const (
	// maxAdvicePaths bounds the changed paths a branch may have for the
	// default branch's side to be read.
	maxAdvicePaths = 300
	// maxMainStatus bounds the lines of MainStatus, the "… and N more" line
	// included.
	maxMainStatus = 20
)

// mainSide fills what the default branch did, since the branch's base, to the
// files the branch changes: the commits it gained, the files it deleted or
// rewrote (and still differs from the branch tip on) and the commits that
// touched them. It leaves the request untouched when the branch has no base.
// A base from the branch's reflog (the default branch's history was
// rewritten) is no ancestor of the default branch: commits "since the fork"
// would be its whole history, so only the file statuses are filled.
func mainSide(ctx context.Context, dir, branch, def string, req *model.WorktreeAdviceRequest) {
	base, viaMergeBase, err := forkBase(ctx, dir, branch, def)
	if err != nil || base == "" {
		return
	}
	if viaMergeBase {
		if n, err := countCommits(ctx, dir, "--no-merges", base+".."+def); err == nil {
			req.Behind = n
		}
	}
	out, err := git(ctx, dir, "diff", "--name-only", "-z", "--no-renames", base, "HEAD")
	if err != nil {
		return
	}
	paths := nulFields(out)
	if len(paths) == 0 || len(paths) > maxAdvicePaths {
		return
	}
	spec := func(args ...string) []string {
		return append(append([]string{"--literal-pathspecs"}, args...), append([]string{"--"}, paths...)...)
	}
	// What the default branch changed since the base, kept where it also
	// differs from the branch tip: a file only the branch touched is the
	// branch's change, and one the branch tip already matches is the merge.
	mainOut, err1 := git(ctx, dir, spec("diff", "--name-status", "-z", "--no-renames", base, def)...)
	tipOut, err2 := git(ctx, dir, spec("diff", "--name-only", "-z", "--no-renames", "HEAD", def)...)
	if err1 == nil && err2 == nil {
		req.MainStatus = mainStatusLines(mainOut, nulFields(tipOut))
	}
	if !viaMergeBase {
		return
	}
	if out, err := git(ctx, dir, spec("log", "--format=%cs %s", "-n", strconv.Itoa(maxAdviceCommits), base+".."+def)...); err == nil {
		for _, s := range strings.Split(strings.TrimSpace(out), "\n") {
			if s != "" {
				req.MainCommits = append(req.MainCommits, s)
			}
		}
	}
}

// nulFields splits NUL-terminated git output.
func nulFields(out string) []string {
	var fields []string
	for _, f := range strings.Split(out, "\x00") {
		if f != "" {
			fields = append(fields, f)
		}
	}
	return fields
}

// mainStatusLines renders `diff --name-status -z` (status and path tokens
// alternate) for the paths in differs, at most maxMainStatus lines.
func mainStatusLines(nameStatus string, differs []string) []string {
	differing := make(map[string]bool, len(differs))
	for _, p := range differs {
		differing[p] = true
	}
	toks := nulFields(nameStatus)
	var lines []string
	for i := 0; i+1 < len(toks); i += 2 {
		if !differing[toks[i+1]] {
			continue
		}
		verb := "changed"
		switch toks[i][0] {
		case 'D':
			verb = "deleted"
		case 'A':
			verb = "added"
		}
		lines = append(lines, verb+" on main: "+toks[i+1])
	}
	if len(lines) > maxMainStatus {
		more := len(lines) - (maxMainStatus - 1)
		lines = append(lines[:maxMainStatus-1], fmt.Sprintf("… and %d more", more))
	}
	return lines
}

// Inspect inspects path now and returns its row and its repository's main
// worktree path.
func (h *Hunter) Inspect(ctx context.Context, path string) (Worktree, string, error) {
	if !filepath.IsAbs(path) {
		return Worktree{}, "", errors.New("path must be absolute")
	}
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	rs, l, err := h.locate(ctx, path)
	if err != nil {
		return Worktree{}, "", err
	}
	return h.judge(ctx, rs, l), rs.ref.Main, nil
}
