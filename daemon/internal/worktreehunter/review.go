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

type NotReviewableError struct{ Row Worktree }

func (e *NotReviewableError) Error() string {
	return fmt.Sprintf("worktree is %s, not safe to move to Trash: %s", e.Row.State, strings.Join(e.Row.Reasons, "; "))
}

// TrashReviewed preserves local-only files in the Trash while unregistering
// a linked worktree. It never relaxes the automatic Remove verdict.
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
	if row.State != StateReview || row.Orphan || row.Error != "" || row.Submodules != 0 {
		return TrashedOrphan{}, &NotReviewableError{Row: row}
	}
	if row.Head != head || !slices.Equal(row.Reasons, reasons) {
		return TrashedOrphan{}, ErrReviewChanged
	}
	// Never move another registered worktree along with this folder.
	for _, other := range rs.list {
		if other.Path != l.Path && strings.HasPrefix(other.Path, l.Path+string(filepath.Separator)) {
			return TrashedOrphan{}, errors.New("another registered worktree is inside this folder")
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
