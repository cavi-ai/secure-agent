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

// RemovalReview binds an explicit permanent-deletion request to the facts
// shown in its confirmation. Branches and committed source remain in git.
type RemovalReview struct {
	Head    string   `json:"head"`
	Reasons []string `json:"reasons"`
}

func reviewedRemoveBlocker(row Worktree) string {
	if why := trashBlocker(row); why != "" {
		return why
	}
	switch {
	case row.State != StateReview:
		return "only an inspected review worktree qualifies"
	case row.Head == "" || len(row.Reasons) == 0:
		return "inspection details are missing"
	case row.Detached || row.Branch == "":
		return "a branch must retain the commits"
	case row.Changed > 0 || row.Untracked > 0:
		return "uncommitted or untracked source must be preserved first"
	case len(row.PreciousIgnored) > 0:
		return "local secrets or agent state must be preserved first"
	}
	return ""
}

func validateRemovalReview(row Worktree, review *RemovalReview) error {
	if row.Head != review.Head || !slices.Equal(row.Reasons, review.Reasons) {
		return ErrReviewChanged
	}
	if reviewedRemoveBlocker(row) != "" {
		return &NotRemovableError{Row: row}
	}
	return nil
}

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
	case row.Operation != "":
		return "a git " + row.Operation + " is in progress; finish or abort it first"
	case len(row.SubmoduleLocal) != 0:
		return strings.Join(row.SubmoduleLocal, "; ")
	case row.InUse:
		return liveAgentReason(row)
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
