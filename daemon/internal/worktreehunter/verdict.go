package worktreehunter

import (
	"fmt"
	"strings"
	"time"
)

// Worktree states.
const (
	StateMain   = "main"   // the repository's main worktree; never removed
	StatePrune  = "prune"  // directory gone; only git's admin entry is left
	StateKeep   = "keep"   // removing it would lose work, or it is in use
	StateReview = "review" // nothing is lost by git, but something only lives here
	StateRemove = "remove" // clean, merged or pushed and idle: safe to remove
)

// Worktree is one row of the report: the facts and the verdict.
type Worktree struct {
	Path     string `json:"path"`
	Branch   string `json:"branch,omitempty"`
	Head     string `json:"head,omitempty"`
	Detached bool   `json:"detached,omitempty"`
	Locked   bool   `json:"locked,omitempty"`
	// LockReason is the text given to `git worktree lock --reason`.
	LockReason string `json:"lock_reason,omitempty"`
	Orphan     bool   `json:"orphan,omitempty"`

	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
	Stale   bool     `json:"stale,omitempty"`

	LastActivity *time.Time `json:"last_activity,omitempty"`
	IdleDays     int        `json:"idle_days"`
	InUse        bool       `json:"in_use,omitempty"`

	Upstream     string `json:"upstream,omitempty"`
	Ahead        int    `json:"ahead,omitempty"`
	Behind       int    `json:"behind,omitempty"`
	UpstreamGone bool   `json:"upstream_gone,omitempty"`

	Changed   int      `json:"changed,omitempty"`
	Untracked int      `json:"untracked,omitempty"`
	Conflicts int      `json:"conflicts,omitempty"`
	Paths     []string `json:"paths,omitempty"`

	// Unique counts commits reachable from HEAD but from no remote ref and
	// not from the default branch. Loose counts, for a detached HEAD, the
	// commits no branch, tag or remote keeps: removal loses those.
	Unique int    `json:"unique_commits,omitempty"`
	Loose  int    `json:"loose_commits,omitempty"`
	Merged string `json:"merged,omitempty"`

	Stashes         int      `json:"stashes,omitempty"`
	PreciousIgnored []string `json:"precious_ignored,omitempty"`
	OtherIgnored    int      `json:"other_ignored,omitempty"`

	Error string `json:"error,omitempty"`
}

// facts carries the inputs classify reads beyond the row itself.
type facts struct {
	Main          bool
	Missing       bool
	DefaultBranch string // short name for reasons
	HeadTime      time.Time
	IndexTime     time.Time
	LastSession   time.Time
}

// classify fills State, Reasons, Stale, LastActivity and IdleDays. Pure:
// the verdict is a function of the facts, so a test pins every rule.
//
// Removal is judged by what `git worktree remove` destroys: the working
// directory. Branches, stashes and every commit a ref reaches survive it.
// keep  = uncommitted or unreachable work, a lock, or a live agent session.
// review = nothing git-tracked is lost, but something only lives here.
// remove = merged, or pushed and idle past staleAfter.
func classify(w *Worktree, f facts, now time.Time, staleAfter time.Duration) {
	last := latest(f.HeadTime, f.IndexTime, f.LastSession)
	if !last.IsZero() {
		w.LastActivity = &last
		w.IdleDays = int(now.Sub(last).Hours() / 24)
	}
	merged := w.Merged == mergedAncestor || w.Merged == mergedSquash || w.Merged == mergedEmpty
	idle := !last.IsZero() && now.Sub(last) > staleAfter
	w.Stale = idle || merged || w.UpstreamGone
	w.Reasons = []string{}

	switch {
	case f.Main:
		w.State = StateMain
		w.Reasons = append(w.Reasons, "main worktree of the repository")
		return
	case f.Missing:
		w.State = StatePrune
		w.Reasons = append(w.Reasons, "directory is gone; git still lists it")
		return
	}

	var keep, review []string
	if w.Locked {
		if w.LockReason != "" {
			keep = append(keep, "locked: "+w.LockReason)
		} else {
			keep = append(keep, "locked")
		}
	}
	if w.Conflicts > 0 {
		keep = append(keep, plural(w.Conflicts, "unresolved conflict", "unresolved conflicts"))
	}
	if w.Changed > 0 {
		keep = append(keep, plural(w.Changed, "uncommitted change", "uncommitted changes"))
	}
	if w.Untracked > 0 {
		keep = append(keep, plural(w.Untracked, "untracked file or directory", "untracked files or directories"))
	}
	if w.Loose > 0 {
		keep = append(keep, fmt.Sprintf("detached HEAD with %s on no branch (removal loses them)", plural(w.Loose, "commit", "commits")))
	}
	if w.InUse {
		keep = append(keep, "an agent session is live here")
	}

	if w.Orphan {
		review = append(review, "directory is not registered with git; its files are the only copy")
	}
	if w.Error != "" {
		review = append(review, "could not inspect: "+w.Error)
	}
	if len(w.PreciousIgnored) > 0 {
		review = append(review, "ignored files that only live here: "+strings.Join(w.PreciousIgnored, ", "))
	}
	if w.Unique > 0 && !merged {
		review = append(review, fmt.Sprintf("%s on no remote and not in %s (the branch keeps them after removal)",
			plural(w.Unique, "commit", "commits"), orDefault(f.DefaultBranch)))
	}
	if w.Stashes > 0 {
		review = append(review, plural(w.Stashes, "stash", "stashes")+" on this branch")
	}

	switch {
	case len(keep) > 0:
		w.State = StateKeep
		w.Reasons = append(keep, review...)
	case len(review) > 0:
		w.State = StateReview
		w.Reasons = review
	case merged:
		w.State = StateRemove
		w.Reasons = append(w.Reasons, mergedReason(w.Merged, f.DefaultBranch))
	case w.Unique == 0 && idle:
		w.State = StateRemove
		w.Reasons = append(w.Reasons, fmt.Sprintf("every commit is on a remote; idle %d days", w.IdleDays))
	default:
		w.State = StateKeep
		if last.IsZero() {
			w.Reasons = append(w.Reasons, "not merged")
		} else {
			w.Reasons = append(w.Reasons, fmt.Sprintf("not merged; active %d days ago", w.IdleDays))
		}
	}
}

func mergedReason(how, def string) string {
	switch how {
	case mergedSquash:
		return "merged into " + orDefault(def) + " (squash)"
	case mergedEmpty:
		return "changes nothing against " + orDefault(def)
	default:
		return "merged into " + orDefault(def)
	}
}

func orDefault(def string) string {
	if def == "" {
		return "the default branch"
	}
	return def
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func latest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if t.After(out) {
			out = t
		}
	}
	return out
}
