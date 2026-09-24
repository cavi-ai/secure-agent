package worktreehunter

import (
	"context"
	"errors"
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
	}
	if row.Unique > 0 {
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
