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

// Reason kinds: what each entry of Reasons says about removing the folder.
const (
	ReasonKeep   = "keep"   // removal would lose work or cut into a git operation
	ReasonAgent  = "agent"  // an agent is working in the folder
	ReasonReview = "review" // something only lives here; look before removing
	ReasonSafe   = "safe"   // the work is kept elsewhere
	ReasonInfo   = "info"   // context
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
	// Reconnect names a known repository whose worktree record still points
	// at this orphan (the repository moved): `git worktree repair` there
	// links it again.
	Reconnect string `json:"reconnect,omitempty"`

	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
	// ReasonKinds holds the kind of each entry of Reasons, in order
	// (ReasonKeep, ReasonAgent, ReasonReview, ReasonSafe, ReasonInfo).
	ReasonKinds []string `json:"reason_kinds"`
	Stale       bool     `json:"stale,omitempty"`

	LastActivity *time.Time `json:"last_activity,omitempty"`
	IdleDays     int        `json:"idle_days"`
	InUse        bool       `json:"in_use,omitempty"`
	// ActiveAgent is the harness of the newest session working in the
	// folder when InUse ("codex"), or "" when it is unknown.
	ActiveAgent string `json:"active_agent,omitempty"`

	Upstream     string `json:"upstream,omitempty"`
	Ahead        int    `json:"ahead,omitempty"`
	Behind       int    `json:"behind,omitempty"`
	UpstreamGone bool   `json:"upstream_gone,omitempty"`

	Changed   int      `json:"changed,omitempty"`
	Untracked int      `json:"untracked,omitempty"`
	Conflicts int      `json:"conflicts,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	// PartlyStaged counts changed files whose staged version differs from
	// the working file: moving the folder would lose the staged version.
	PartlyStaged int    `json:"partly_staged,omitempty"`
	Operation    string `json:"git_operation,omitempty"`

	// Unique counts commits reachable from HEAD but from no remote ref and
	// not from the default branch. Loose counts, for a detached HEAD, the
	// commits no branch, tag or remote keeps: removal loses those.
	Unique int    `json:"unique_commits,omitempty"`
	Loose  int    `json:"loose_commits,omitempty"`
	Merged string `json:"merged,omitempty"`
	// ContentLines counts the non-blank lines the branch adds over its merge
	// base, and ContentMissing those the default branch does not have. Both
	// are set when the content check ran to the end.
	ContentLines   int `json:"content_lines,omitempty"`
	ContentMissing int `json:"content_missing,omitempty"`
	// ContentExtended counts the added lines the default branch has only in
	// a longer form (a list or import it extended); they are not missing.
	ContentExtended int `json:"content_extended,omitempty"`
	// ContentOther counts the other differences: lines or files the branch
	// removes that the default branch still has, binaries and file modes.
	ContentOther int `json:"content_other,omitempty"`
	// Unrelated marks a HEAD that shares no commit with the default branch
	// (its history was rewritten): the content check then measures from the
	// branch's creation point, and Unique counts the old history too.
	Unrelated bool `json:"unrelated_history,omitempty"`

	// SizeBytes is the allocated size of the working directory, measured by
	// the background sizer; SizePartial marks a walk that hit its bound.
	SizeBytes   int64 `json:"size_bytes,omitempty"`
	SizePartial bool  `json:"size_partial,omitempty"`

	// Submodules counts populated submodules; SubmoduleLocal names work in
	// them no remote has, which removal would lose.
	Submodules     int      `json:"submodules,omitempty"`
	SubmoduleLocal []string `json:"submodule_local,omitempty"`

	Stashes         int      `json:"stashes,omitempty"`
	PreciousIgnored []string `json:"precious_ignored,omitempty"`
	// ScratchIgnored lists ignored scratch directories (.tmp): they block an
	// unmerged branch and go with a merged one.
	ScratchIgnored []string `json:"scratch_ignored,omitempty"`
	OtherIgnored   int      `json:"other_ignored,omitempty"`

	Error string `json:"error,omitempty"`
}

// activeGrace keeps a worktree touched in the last day off the remove list
// when its merge is ancestry or an empty diff: a fresh worktree an agent is
// about to use has no commits of its own and reads that way, and its session
// may be recorded at the repo root. A squash merge is landed work.
const activeGrace = 24 * time.Hour

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
// review = nothing git-tracked is lost, but something only lives here
// (scratch counts only while the branch is unmerged).
// remove = squash-merged; merged by ancestry or an empty diff and untouched
// for activeGrace; or pushed and idle past staleAfter.
func classify(w *Worktree, f facts, now time.Time, staleAfter time.Duration) {
	last := latest(f.HeadTime, f.IndexTime, f.LastSession)
	if !last.IsZero() {
		w.LastActivity = &last
		w.IdleDays = int(now.Sub(last).Hours() / 24)
	}
	merged := isMerged(w.Merged)
	idle := !last.IsZero() && now.Sub(last) > staleAfter
	recent := !last.IsZero() && now.Sub(last) < activeGrace
	w.Stale = idle || ((merged || w.UpstreamGone) && !recent)
	w.Reasons, w.ReasonKinds = []string{}, []string{}

	switch {
	case f.Main:
		w.State = StateMain
		w.reason(ReasonInfo, "main worktree of the repository")
		return
	case f.Missing && w.Locked:
		// git worktree prune skips locked entries.
		w.State = StateKeep
		w.reason(ReasonKeep, lockedReason(w))
		w.reason(ReasonInfo, "directory is gone; unlock it to prune")
		return
	case f.Missing:
		w.State = StatePrune
		w.reason(ReasonInfo, "directory is gone; git still lists it")
		return
	}

	type entry struct{ kind, text string }
	var keep, review []entry
	if w.Operation != "" {
		keep = append(keep, entry{ReasonKeep, "a git " + w.Operation + " is in progress; finish or abort it first"})
	}
	if w.Locked {
		keep = append(keep, entry{ReasonKeep, lockedReason(w)})
	}
	if w.Conflicts > 0 {
		keep = append(keep, entry{ReasonKeep, plural(w.Conflicts, "unresolved conflict", "unresolved conflicts")})
	}
	if w.Changed > 0 {
		keep = append(keep, entry{ReasonKeep, plural(w.Changed, "uncommitted change", "uncommitted changes")})
	}
	if w.Untracked > 0 {
		keep = append(keep, entry{ReasonKeep, plural(w.Untracked, "untracked file or directory", "untracked files or directories")})
	}
	if w.Loose > 0 {
		keep = append(keep, entry{ReasonKeep, fmt.Sprintf("detached HEAD with %s on no branch (removal loses them)", plural(w.Loose, "commit", "commits"))})
	}
	if w.InUse {
		keep = append(keep, entry{ReasonAgent, liveAgentReason(*w)})
	}
	for _, s := range w.SubmoduleLocal {
		keep = append(keep, entry{ReasonKeep, s})
	}

	if w.Orphan {
		review = append(review, entry{ReasonReview, "directory is not registered with git; its files are the only copy"})
	}
	if w.Error != "" {
		review = append(review, entry{ReasonReview, "could not inspect: " + w.Error})
	}
	if len(w.PreciousIgnored) > 0 {
		review = append(review, entry{ReasonReview, "ignored files that only live here: " + strings.Join(w.PreciousIgnored, ", ")})
	}
	if len(w.ScratchIgnored) > 0 && !merged {
		review = append(review, entry{ReasonReview, "scratch files that only live here: " + strings.Join(w.ScratchIgnored, ", ")})
	}
	def := orDefault(f.DefaultBranch)
	longer := ""
	if w.ContentExtended > 0 {
		longer = fmt.Sprintf(" (%s only in a longer form)", plural(w.ContentExtended, "line", "lines"))
	}
	// differs names what else keeps a measured branch from matching.
	differs := ""
	switch {
	case w.ContentOther == 1:
		differs = "1 line or file it removes or changes still differs on " + def
	case w.ContentOther > 1:
		differs = fmt.Sprintf("%d lines or files it removes or changes still differ on %s", w.ContentOther, def)
	}
	if w.Unique > 0 && !merged {
		// A detached HEAD has no branch to keep them; Loose says what is lost.
		kept, keeps := " (the branch keeps them after removal)", "; the branch keeps its commits after removal"
		if w.Detached {
			kept, keeps = "", ""
		}
		reason := fmt.Sprintf("%s on no remote and not in %s%s",
			plural(w.Unique, "commit", "commits"), def, kept)
		var measure []string
		if w.ContentLines > 0 {
			added := "they add"
			if w.Unrelated {
				added = "it added since it was created"
			}
			measure = append(measure, fmt.Sprintf("%d of %d lines %s are on %s%s", w.ContentLines-w.ContentMissing, w.ContentLines, added, def, longer))
		}
		if differs != "" {
			measure = append(measure, differs)
		}
		switch {
		case w.Unrelated && len(measure) > 0:
			reason = "shares no history with " + def + " (rewritten); " + strings.Join(measure, "; ") + keeps
		case w.Unrelated:
			reason += "; it shares no history with " + def + " (rewritten)"
		case len(measure) > 0:
			reason += "; " + strings.Join(measure, "; ")
		}
		review = append(review, entry{ReasonReview, reason})
	}
	mr := mergedReason(w.Merged, f.DefaultBranch)
	if w.Stashes > 0 {
		review = append(review, entry{ReasonReview, plural(w.Stashes, "stash", "stashes") + " on this branch"})
	}

	switch {
	case len(keep) > 0 || len(review) > 0:
		w.State = StateReview
		if len(keep) > 0 {
			w.State = StateKeep
		}
		for _, e := range append(keep, review...) {
			w.reason(e.kind, e.text)
		}
		if merged {
			w.reason(ReasonSafe, mr)
		}
	case merged && recent && w.Merged != mergedSquash:
		w.State = StateKeep
		w.reason(ReasonInfo, mr+"; active in the last 24 hours")
	case merged:
		w.State = StateRemove
		w.reason(ReasonSafe, mr)
	case w.Unique == 0 && idle:
		w.State = StateRemove
		w.reason(ReasonSafe, fmt.Sprintf("every commit is on a remote; idle %d days", w.IdleDays))
	default:
		w.State = StateKeep
		if last.IsZero() {
			w.reason(ReasonInfo, "not merged")
		} else {
			w.reason(ReasonInfo, fmt.Sprintf("not merged; active %d days ago", w.IdleDays))
		}
	}
	if w.State == StateRemove && w.Submodules > 0 {
		w.reason(ReasonSafe, plural(w.Submodules, "submodule", "submodules")+" with every commit on a remote")
	}
	if merged && len(w.ScratchIgnored) > 0 {
		w.reason(ReasonInfo, "scratch files go with the folder: "+strings.Join(w.ScratchIgnored, ", "))
	}
}

// reason appends text to Reasons and its kind to ReasonKinds.
func (w *Worktree) reason(kind, text string) {
	w.Reasons = append(w.Reasons, text)
	w.ReasonKinds = append(w.ReasonKinds, kind)
}

// liveAgentReason names the agent working in a worktree, when known.
func liveAgentReason(w Worktree) string {
	if w.ActiveAgent != "" {
		return w.ActiveAgent + " is working here"
	}
	return "an agent session is live here"
}

func lockedReason(w *Worktree) string {
	if w.LockReason != "" {
		return "locked: " + w.LockReason
	}
	return "locked"
}

// isMerged reports whether a merge verdict says the branch's work is already
// on the default branch.
func isMerged(how string) bool {
	switch how {
	case mergedAncestor, mergedSquash, mergedEmpty:
		return true
	}
	return false
}

func mergedReason(how, def string) string {
	switch how {
	case mergedSquash:
		return "merged into " + orDefault(def) + " (squash)"
	case mergedEmpty:
		return "changes nothing against " + orDefault(def)
	default:
		// Ancestry covers a merged branch and a fresh one with no commits
		// of its own alike: name the fact, not a merge.
		return "no commits outside " + orDefault(def)
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
