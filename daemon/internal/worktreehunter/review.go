package worktreehunter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/trash"
)

var ErrReviewChanged = errors.New("worktree changed since review; refresh and inspect it again")

type NotReviewableError struct {
	Row Worktree
	// Why names the single reason this row cannot go to the Trash.
	Why string
}

func (e *NotReviewableError) Error() string {
	if e.Why != "" {
		return fmt.Sprintf("worktree is %s, not safe to move to Trash: %s", e.Row.State, e.Why)
	}
	return fmt.Sprintf("worktree is %s, not safe to move to Trash: %s", e.Row.State, strings.Join(e.Row.Reasons, "; "))
}

// trashBlocker returns why a keep or review row cannot be moved to the
// Trash, or "". The move may lose only the folder: nothing a live session
// holds, nothing git protects with a lock, no commit that only the detached
// HEAD reaches, and nothing only the worktree's index or merge state holds
// (git deletes those with the registration).
func trashBlocker(row Worktree) string {
	switch {
	case row.Orphan:
		return "directory is not registered with git"
	case row.Error != "":
		return "could not inspect: " + row.Error
	case row.Submodules != 0:
		return "it has populated submodules"
	case row.InUse:
		return "an agent session is live here"
	case row.Locked:
		return "it is locked; unlock it first"
	case row.Loose > 0:
		return "detached HEAD has commits on no branch; create a branch first"
	case row.Conflicts > 0:
		return "a merge or rebase has unresolved conflicts; finish or abort it first"
	case row.PartlyStaged > 0:
		return plural(row.PartlyStaged, "file has", "files have") + " staged changes that differ from the working copy; commit or unstage them first"
	}
	return ""
}

// TrashReviewed moves a linked worktree's folder to the Trash and
// unregisters it from git. A keep or review row qualifies; the folder goes
// with its uncommitted, untracked and ignored files (recoverable from the
// Trash), while the branch, its commits and stashes stay in git. It refuses
// what trashBlocker names and a folder holding another registered worktree.
// It never relaxes the automatic Remove verdict.
func (h *Hunter) TrashReviewed(ctx context.Context, path, head string, reasons []string) (TrashedOrphan, error) {
	if !filepath.IsAbs(path) || head == "" || len(reasons) == 0 {
		return TrashedOrphan{}, errors.New("absolute path, reviewed head and reasons are required")
	}
	defer h.lockForAction(nil)()
	ctx = context.WithoutCancel(ctx)
	rs, l, err := h.locate(ctx, path)
	if err != nil {
		return TrashedOrphan{}, err
	}
	row := h.judge(ctx, rs, l)
	if row.State != StateKeep && row.State != StateReview {
		return TrashedOrphan{}, &NotReviewableError{Row: row}
	}
	if why := trashBlocker(row); why != "" {
		return TrashedOrphan{}, &NotReviewableError{Row: row, Why: why}
	}
	if row.Head != head || !slices.Equal(row.Reasons, reasons) {
		return TrashedOrphan{}, ErrReviewChanged
	}
	// Never move another registered worktree along with this folder.
	for _, other := range rs.list {
		if other.Path != l.Path && strings.HasPrefix(other.Path, l.Path+string(filepath.Separator)) {
			return TrashedOrphan{}, &NotReviewableError{Row: row, Why: "another registered worktree is inside this folder"}
		}
	}
	u := diskusage.Dir(ctx, l.Path, nil)
	dest, err := (trash.Mover{Home: h.home, GOOS: h.goos, Now: h.now}).Move(l.Path)
	if err != nil {
		return TrashedOrphan{}, err
	}
	if _, err := gitWithin(ctx, removeTimeout, rs.ref.Main, "worktree", "remove", "--force", l.Path); err != nil {
		if rollbackErr := os.Rename(dest, l.Path); rollbackErr != nil {
			h.st.PutAudit(store.AuditEntry{Action: "worktree-review-trash-rollback-failed", Detail: fmt.Sprintf("path=%s trash=%s git_error=%v rollback_error=%v", l.Path, dest, err, rollbackErr)})
			return TrashedOrphan{}, fmt.Errorf("git unregister failed: %w; rollback failed: %v; files are at %s", err, rollbackErr, dest)
		}
		return TrashedOrphan{}, fmt.Errorf("git unregister failed; folder restored: %w", err)
	}
	h.st.PutAudit(store.AuditEntry{Action: "worktree-review-trash", Detail: fmt.Sprintf("path=%s trash=%s branch=%s head=%s", l.Path, dest, orDetached(l.Branch), row.Head)})
	h.st.PutCleanup(model.CleanupEntry{TS: h.now(), Action: "trash:review-worktree", Path: l.Path, Repo: rs.ref.Main, Bytes: u.Bytes,
		Detail: "branch " + orDetached(l.Branch) + " kept; folder moved to " + dest})
	h.forgetSize(l.Path)
	h.dropRow(l.Path)
	return TrashedOrphan{Path: l.Path, Bytes: u.Bytes, TrashPath: dest}, nil
}
