package worktreehunter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/trash"
)

// ErrRepoMissing is the error of a group whose repository is gone while
// worktree folders still point into it.
const ErrRepoMissing = "repository not found (moved or deleted)"

var (
	// ErrNotOrphan refuses an orphan action on a path that is not a
	// worktree folder whose repository no longer records it.
	ErrNotOrphan = errors.New("not a worktree folder whose repository no longer records it")
	// ErrNoReconnect refuses a reconnect when no known repository still
	// records the folder.
	ErrNoReconnect = errors.New("no known repository still records this worktree; git cannot link it again")
)

// reconnectCandidate returns a scanned repository whose worktree record
// named o.Name still points at o.Path: the repository moved and `git
// worktree repair` there links the folder again.
func reconnectCandidate(repos []RepoReport, o orphanDir) string {
	if o.Name == "" {
		return ""
	}
	for _, r := range repos {
		if r.Error != "" {
			continue
		}
		common := r.Path
		if !r.Bare {
			common = filepath.Join(r.Path, ".git")
		}
		b, err := os.ReadFile(filepath.Join(common, "worktrees", o.Name, "gitdir"))
		if err != nil {
			continue
		}
		if canonical(filepath.Dir(strings.TrimSpace(string(b)))) == o.Path {
			return r.Path
		}
	}
	return ""
}

// orphanAt inspects path now: an orphan when its .git file names an admin
// entry that no longer exists.
func orphanAt(path string) (orphanDir, bool) {
	if !filepath.IsAbs(path) {
		return orphanDir{}, false
	}
	_, o, ok := resolveRepo(path)
	if ok || o == nil || o.Path != canonical(path) {
		return orphanDir{}, false
	}
	return *o, true
}

// Reconnect runs `git worktree repair` in the repository that still
// records the orphan at path and returns that repository.
func (h *Hunter) Reconnect(ctx context.Context, path string) (string, error) {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	o, ok := orphanAt(path)
	if !ok {
		return "", ErrNotOrphan
	}
	h.mu.Lock()
	var repos []RepoReport
	if h.cached != nil {
		repos = h.cached.Repos
	}
	h.mu.Unlock()
	repo := reconnectCandidate(repos, o)
	if repo == "" {
		return "", ErrNoReconnect
	}
	if _, err := git(context.WithoutCancel(ctx), repo, "worktree", "repair", o.Path); err != nil {
		return "", err
	}
	if _, _, linked := resolveRepo(o.Path); !linked {
		return "", fmt.Errorf("git worktree repair ran in %s but %s is still not linked", repo, o.Path)
	}
	h.st.PutAudit(store.AuditEntry{Action: "worktree-reconnect", Detail: fmt.Sprintf("path=%s repo=%s", o.Path, repo)})
	h.markStale()
	return repo, nil
}

// TrashedOrphan is what moving an orphan to the Trash gave back.
type TrashedOrphan struct {
	Path      string `json:"path"`
	Bytes     int64  `json:"bytes"`
	TrashPath string `json:"trash_path"`
}

// TrashOrphan moves the orphan folder at path to the Trash on its volume
// and books its size as trashed.
func (h *Hunter) TrashOrphan(ctx context.Context, path string) (TrashedOrphan, error) {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	o, ok := orphanAt(path)
	if !ok {
		return TrashedOrphan{}, ErrNotOrphan
	}
	u := diskusage.Dir(context.WithoutCancel(ctx), o.Path, nil)
	dest, err := trash.Mover{Home: h.home, GOOS: h.goos, Now: h.now}.Move(o.Path)
	if err != nil {
		return TrashedOrphan{}, err
	}
	h.st.PutAudit(store.AuditEntry{Action: "worktree-trash-orphan", Detail: fmt.Sprintf("path=%s trash=%s", o.Path, dest)})
	h.st.PutCleanup(model.CleanupEntry{TS: h.now(), Action: "trash:orphan-worktree", Path: o.Path, Repo: o.Main, Bytes: u.Bytes,
		Detail: "moved to " + dest})
	h.forgetSize(o.Path)
	h.dropRow(o.Path)
	return TrashedOrphan{Path: o.Path, Bytes: u.Bytes, TrashPath: dest}, nil
}

// Listed reports whether path is a row of the cached scan.
func (h *Hunter) Listed(path string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached == nil {
		return false
	}
	for _, r := range h.cached.Repos {
		for _, w := range r.Worktrees {
			if w.Path == path {
				return true
			}
		}
	}
	return false
}

// markStale keeps the cached scan answering while the next report
// rescans in the background.
func (h *Hunter) markStale() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cachedAt = time.Time{}
}
