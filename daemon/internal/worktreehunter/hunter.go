// Package worktreehunter is the worktree hunter: it finds every git worktree on
// the machine (from agent session workspaces, the directories agent apps keep
// worktrees in, configured scan roots and a saved repo list), inspects each
// one read-only, and says whether it can be removed and why.
//
// Invariants:
//   - Read-only toward the repositories: GIT_OPTIONAL_LOCKS=0, no fetch, no
//     object writes, no network. Merge detection is local (ancestry, then a
//     patch-id match for squash merges, then a match of the added lines).
//   - Scans run one at a time, only on an asked refresh or when no scan is
//     cached; a report read answers from the cached scan at any age, and row
//     actions edit that scan in place.
//   - The verdict is deterministic (classify). Nothing outside the facts
//     can turn keep into remove.
package worktreehunter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Store is what the hunter reads and records. *store.Store satisfies it.
type Store interface {
	WorktreeRepos() []model.WorktreeRepo
	UpsertWorktreeRepo(path, source string, at time.Time)
	SetWorktreeRepoHidden(path string, hidden bool) bool
	WorkspaceActivity() []model.WorkspaceActivity
	PutAudit(store.AuditEntry)
	PutCleanup(model.CleanupEntry)
	ScanCache(name string) ([]byte, time.Time, bool)
	PutScanCache(name string, body []byte, at time.Time)
	DeleteScanCache(name string)
}

// Options are the operator's knobs (config `worktrees:`).
type Options struct {
	Roots     []string
	StaleDays int
}

const (
	// DefaultStaleDays is the idle age that marks a worktree stale.
	DefaultStaleDays = 14
	// minRescan is the floor under refresh: a console or script asking for a
	// rescan in a loop gets the last scan instead of a git process storm.
	minRescan = 30 * time.Second
	// scanTimeout bounds one full scan.
	scanTimeout = 3 * time.Minute
	// workers bounds concurrent git work across the scan.
	workers = 4
)

// ScanReport is one scan's result.
type ScanReport struct {
	GeneratedAt time.Time    `json:"generated_at"`
	DurationMS  int64        `json:"duration_ms"`
	Cached      bool         `json:"cached"`
	StaleDays   int          `json:"stale_days"`
	Summary     ScanSummary  `json:"summary"`
	Repos       []RepoReport `json:"repos"`
	Errors      []string     `json:"errors,omitempty"`
	// Sizing is true while some worktrees still wait for the background
	// sizer; their size is missing and the totals are lower bounds.
	Sizing bool `json:"sizing,omitempty"`
	// Refreshing is true while the background sizer re-measures sizes this
	// report already shows.
	Refreshing bool `json:"refreshing,omitempty"`
	// Removals are the running removals and those that ended in the last
	// 30 minutes, by path.
	Removals map[string]Removal `json:"removals,omitempty"`
	// Volumes are the disks holding the scanned repositories.
	Volumes []diskusage.Volume `json:"volumes,omitempty"`
	// Reclaimed sums the cleanup ledger; the API fills it.
	Reclaimed *model.CleanupTotals `json:"reclaimed,omitempty"`
	// Asks holds the latest request to each worktree's owning agent, by
	// path; the API fills it.
	Asks map[string]model.AgentAsk `json:"asks,omitempty"`
	// Askable lists worktrees with a live, identified agent session.
	Askable map[string]string `json:"askable,omitempty"`
	// Advice holds the local advisor's note per worktree path, for notes
	// taken at the row's current HEAD. The API fills it on its copy of the
	// report; the scan never reads it.
	Advice map[string]model.AdvisorVerdict `json:"advice,omitempty"`
}

// ScanSummary counts rows by state. Worktrees excludes main rows.
type ScanSummary struct {
	Repos     int `json:"repos"`
	Worktrees int `json:"worktrees"`
	Remove    int `json:"remove"`
	Review    int `json:"review"`
	Keep      int `json:"keep"`
	Prune     int `json:"prune"`
	Stale     int `json:"stale"`
	// SizeBytes and RemovableBytes sum the measured worktrees (all, and
	// those in state remove); while Sizing, they are lower bounds.
	SizeBytes      int64 `json:"size_bytes"`
	RemovableBytes int64 `json:"removable_bytes"`
}

// RepoReport groups one repository's worktrees; the main worktree comes first.
type RepoReport struct {
	Path          string `json:"path"`
	Source        string `json:"source,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
	Bare          bool   `json:"bare,omitempty"`
	// SizeBytes sums the repository's measured linked worktrees (the main
	// worktree is never removable, so it is not measured).
	SizeBytes int64      `json:"size_bytes"`
	Worktrees []Worktree `json:"worktrees"`
	Error     string     `json:"error,omitempty"`
}

// Hunter owns scans and their cache.
type Hunter struct {
	st   Store
	home string
	now  func() time.Time
	// goos picks the Trash layout (macOS or freedesktop); tests pin it.
	goos string

	mu       sync.Mutex
	opts     Options
	cached   *ScanReport
	cachedAt time.Time
	// An invalidation can finish during a scan. Only scans that started
	// after the last invalidation can publish a report.
	cacheGeneration uint64

	// scanMu serializes scans and row actions; a request that waited on it
	// reuses the scan that finished meanwhile.
	scanMu sync.Mutex
	// loaded is guarded by scanMu and is set once the saved report and
	// sizes have been read from the store.
	loaded bool

	// removals tracks each removal's steps and outcome by path; remWG lets
	// tests wait for background removals.
	remMu    sync.Mutex
	removals map[string]*Removal
	remWG    sync.WaitGroup

	fpMu sync.Mutex
	// fingerprints caches each repository's default-branch patch ids by
	// the branch tip they were computed at.
	fingerprints map[string]fingerprintCache

	pathMu sync.Mutex
	// pathIndexes caches each repository's default-branch path index by the
	// branch tip it was read at.
	pathIndexes map[string]pathCache

	// sizes caches measured worktree sizes by path; sizing is true while
	// the background sizer runs (one at a time); sizesSaved is when the
	// sizer last saved them; sizeWG lets tests wait.
	sizeMu     sync.Mutex
	sizes      map[string]sizeEntry
	sizing     bool
	sizesSaved time.Time
	sizeWG     sync.WaitGroup
}

type fingerprintCache struct {
	tip string
	ids map[string]bool
}

type pathCache struct {
	tip string
	ix  *pathIndex
}

// New builds a hunter. home "" resolves to the user's home directory.
func New(st Store, home string, opts Options) *Hunter {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return &Hunter{st: st, home: home, now: time.Now, goos: runtime.GOOS, opts: normalize(opts),
		fingerprints: map[string]fingerprintCache{}, pathIndexes: map[string]pathCache{}, sizes: map[string]sizeEntry{}, removals: map[string]*Removal{}}
}

func staleDuration(days int) time.Duration { return time.Duration(days) * 24 * time.Hour }

func normalize(o Options) Options {
	if o.StaleDays <= 0 {
		o.StaleDays = DefaultStaleDays
	}
	return o
}

// SetOptions applies a config change and drops the cached report.
func (h *Hunter) SetOptions(o Options) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.opts = normalize(o)
	h.invalidateLocked()
}

// Options returns the options in effect.
func (h *Hunter) Options() Options {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opts
}

// invalidateLocked drops both copies of the cached scan. Caller holds mu.
func (h *Hunter) invalidateLocked() {
	h.cacheGeneration++
	h.cached = nil
	h.st.DeleteScanCache(cacheReportKey)
}

// Report returns the scan with sizes and volume usage laid over it. Sizes
// come from the size cache; worktrees not measured yet are queued for the
// background sizer and the report says Sizing.
func (h *Hunter) Report(ctx context.Context, refresh bool) ScanReport {
	rep := h.withSizes(h.report(ctx, refresh), refresh)
	if rm := h.Removals(); len(rm) > 0 {
		rep.Removals = rm
	}
	return rep
}

// Wait returns once the removals and sizing passes started so far have
// finished.
func (h *Hunter) Wait() {
	h.remWG.Wait()
	h.sizeWG.Wait()
}

// report answers from the cached scan at any age unless refresh is asked.
// Without a cached scan, or on refresh, it scans under its own deadline,
// detached from ctx's cancellation, so a client that gives up still leaves
// a finished report for the next request.
func (h *Hunter) report(ctx context.Context, refresh bool) ScanReport {
	asked := h.now()
	if r, ok := h.fresh(refresh, time.Time{}); ok {
		return r
	}
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	h.loadLocked()
	if r, ok := h.fresh(refresh, asked); ok {
		return r
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), scanTimeout)
	defer cancel()
	return h.scanLocked(sctx)
}

// scanLocked scans, caches and saves the report. Caller holds scanMu.
func (h *Hunter) scanLocked(ctx context.Context) ScanReport {
	h.mu.Lock()
	opts, generation := h.opts, h.cacheGeneration
	h.mu.Unlock()
	rep := h.scan(ctx, opts)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cacheGeneration == generation {
		h.saveReportLocked(rep, h.now())
	}
	return rep
}

// saveReportLocked updates the in-memory and saved reports. Caller holds mu.
func (h *Hunter) saveReportLocked(rep ScanReport, at time.Time) {
	h.cached, h.cachedAt = &rep, at
	if body, err := json.Marshal(savedReport{Options: h.opts, Report: rep}); err == nil {
		h.st.PutScanCache(cacheReportKey, body, at)
	}
}

// lockForAction takes the scan lock and loads the saved report before a row
// action, so no scan interleaves with the action. It returns the unlock.
// waiting runs when the lock is not free at once.
func (h *Hunter) lockForAction(waiting func()) func() {
	if !h.scanMu.TryLock() {
		if waiting != nil {
			waiting()
		}
		h.scanMu.Lock()
	}
	h.loadLocked()
	return h.scanMu.Unlock
}

// dropFromCache takes rows (by path) and repository groups (by repository
// path) out of the cached scan, with the error lines of the groups it
// empties, recomputes the summary and saves it under the scan's own time.
// Callers hold the scan lock.
func (h *Hunter) dropFromCache(rows, repos map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached == nil {
		return
	}
	rep := *h.cached
	rep.Repos = nil
	gone := map[string]bool{}
	for _, r := range h.cached.Repos {
		if repos[r.Path] {
			gone[r.Path] = true
			continue
		}
		kept := make([]Worktree, 0, len(r.Worktrees))
		for _, w := range r.Worktrees {
			if !rows[w.Path] {
				kept = append(kept, w)
			}
		}
		if r.Error == ErrRepoMissing && len(kept) == 0 {
			gone[r.Path] = true
			continue
		}
		r.Worktrees = kept
		rep.Repos = append(rep.Repos, r)
	}
	rep.Errors = nil
	for _, e := range h.cached.Errors {
		if repo, _, _ := strings.Cut(e, ": "); !gone[repo] {
			rep.Errors = append(rep.Errors, e)
		}
	}
	rep.Summary = summarize(rep.Repos)
	h.saveReportLocked(rep, h.cachedAt)
}

const (
	cacheReportKey = "worktrees.report"
	cacheSizesKey  = "worktrees.sizes"
)

// savedReport is the stored scan with the options it was taken under; a
// scan under other options is not loaded.
type savedReport struct {
	Options Options    `json:"options"`
	Report  ScanReport `json:"report"`
}

// kindsAligned reports whether every row carries one kind per reason; a
// report saved without reason kinds is rescanned rather than served.
func kindsAligned(rep ScanReport) bool {
	for _, r := range rep.Repos {
		for _, w := range r.Worktrees {
			if len(w.ReasonKinds) != len(w.Reasons) {
				return false
			}
		}
	}
	return true
}

// savedSize is one stored measurement.
type savedSize struct {
	Bytes   int64     `json:"bytes"`
	Partial bool      `json:"partial,omitempty"`
	At      time.Time `json:"at"`
}

// loadLocked reads saved sizes and the report once. Caller holds scanMu.
func (h *Hunter) loadLocked() {
	if h.loaded {
		return
	}
	h.loaded = true
	if body, _, ok := h.st.ScanCache(cacheSizesKey); ok {
		var saved map[string]savedSize
		if json.Unmarshal(body, &saved) == nil {
			h.sizeMu.Lock()
			for p, s := range saved {
				if _, have := h.sizes[p]; !have {
					h.sizes[p] = sizeEntry{bytes: s.Bytes, partial: s.Partial, at: s.At}
				}
			}
			h.sizeMu.Unlock()
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if body, at, ok := h.st.ScanCache(cacheReportKey); ok {
		var saved savedReport
		if json.Unmarshal(body, &saved) == nil && reflect.DeepEqual(normalize(saved.Options), h.opts) && kindsAligned(saved.Report) {
			h.cached, h.cachedAt = &saved.Report, at
		}
	}
}

// fresh returns the cached report when it may answer: at any age without
// refresh; on refresh, younger than minRescan or finished after `after` (a
// scan that completed while this request waited).
func (h *Hunter) fresh(refresh bool, after time.Time) (ScanReport, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached == nil {
		return ScanReport{}, false
	}
	if !refresh || (!after.IsZero() && h.cachedAt.After(after)) || h.now().Sub(h.cachedAt) < minRescan {
		r := *h.cached
		r.Cached = true
		return r, true
	}
	return ScanReport{}, false
}

// ErrNotRepo is returned for a path that is not inside a git repository.
var ErrNotRepo = errors.New("not inside a git repository")

// AddRepo puts the repository containing path on the saved list as manual
// (unhiding it if hidden) and returns its main worktree path. It drops the
// cached scan, so the next report scans once.
func (h *Hunter) AddRepo(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	ref, _, ok := resolveRepo(path)
	if !ok {
		return "", ErrNotRepo
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.invalidateLocked()
	h.st.UpsertWorktreeRepo(ref.Main, model.RepoSourceManual, h.now())
	return ref.Main, nil
}

// HideRepo hides a saved repository from reports and takes its group out
// of the cached scan. path may be any directory inside it. Reports whether
// the repo was on the list.
func (h *Hunter) HideRepo(path string) bool {
	key := canonical(path)
	if ref, _, ok := resolveRepo(path); ok {
		key = ref.Main
	}
	defer h.lockForAction(nil)()
	ok := h.st.SetWorktreeRepoHidden(key, true)
	if ok {
		h.dropFromCache(nil, map[string]bool{key: true})
	}
	return ok
}

// repoScan is one repository's shared state during a scan.
type repoScan struct {
	ref     repoRef
	out     *RepoReport
	def     string // full default ref
	list    []listed
	stashes map[string]int

	fpOnce sync.Once
	fp     map[string]bool
	fpErr  error

	pathOnce sync.Once
	paths    *pathIndex
	pathErr  error
}

func (h *Hunter) scan(ctx context.Context, opts Options) ScanReport {
	start := h.now()
	activity := h.st.WorkspaceActivity()
	d := discover(ctx, discoverInput{Home: h.home, Roots: opts.Roots, Saved: h.st.WorktreeRepos(), Workspaces: activity})
	for _, f := range d.Repos {
		h.st.UpsertWorktreeRepo(f.Ref.Main, f.Source, start)
	}
	source := map[string]string{}
	for _, r := range h.st.WorktreeRepos() {
		source[r.Path] = r.Source
	}

	repos := make([]RepoReport, len(d.Repos))
	scans := make([]*repoScan, len(d.Repos))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, f := range d.Repos {
		repos[i] = RepoReport{Path: f.Ref.Main, Source: source[f.Ref.Main], Bare: f.Ref.Bare}
		scans[i] = &repoScan{ref: f.Ref, out: &repos[i]}
		wg.Add(1)
		go func(rs *repoScan) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			h.prepareRepo(ctx, rs)
		}(scans[i])
	}
	wg.Wait()

	now := h.now()
	staleAfter := staleDuration(opts.StaleDays)
	for _, rs := range scans {
		rs.out.Worktrees = make([]Worktree, len(rs.list))
		for j, l := range rs.list {
			wg.Add(1)
			go func(rs *repoScan, j int, l listed) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				w, f := h.inspectOne(ctx, rs, j == 0, l, activity)
				classify(&w, f, now, staleAfter)
				rs.out.Worktrees[j] = w
			}(rs, j, l)
		}
	}
	wg.Wait()

	rep := ScanReport{GeneratedAt: start.UTC(), StaleDays: opts.StaleDays}
	for i := range repos {
		rep.Repos = append(rep.Repos, dropBare(repos[i]))
	}
	rep.Repos = attachOrphans(rep.Repos, d.Orphans, activity, now, staleAfter)
	sort.Slice(rep.Repos, func(i, j int) bool { return rep.Repos[i].Path < rep.Repos[j].Path })
	for _, r := range rep.Repos {
		if r.Error == "" {
			continue
		}
		line := r.Path + ": " + r.Error
		if r.Error == ErrRepoMissing && len(r.Worktrees) > 0 {
			line += "; " + plural(len(r.Worktrees), "folder still points", "folders still point") + " to it"
		}
		rep.Errors = append(rep.Errors, line)
	}
	rep.Summary = summarize(rep.Repos)
	if ctx.Err() != nil {
		rep.Errors = append(rep.Errors, "scan stopped early: "+ctx.Err().Error())
	}
	rep.DurationMS = h.now().Sub(start).Milliseconds()
	return rep
}

// prepareRepo reads what every worktree of the repo shares: the worktree
// list, the default branch and the stash list.
func (h *Hunter) prepareRepo(ctx context.Context, rs *repoScan) {
	list, err := listWorktrees(ctx, rs.ref.Main)
	if err != nil {
		rs.out.Error = err.Error()
		return
	}
	rs.list = list
	rs.def = defaultBranch(ctx, rs.ref.Main)
	rs.out.DefaultBranch = shortRef(rs.def)
	rs.stashes = branchStashes(ctx, rs.ref.Main)
}

// repoFingerprints returns the default branch's patch ids, computed at most
// once per scan and reused across scans while the branch tip is unchanged.
func (h *Hunter) repoFingerprints(ctx context.Context, rs *repoScan) (map[string]bool, error) {
	rs.fpOnce.Do(func() {
		tipOut, err := git(ctx, rs.ref.Main, "rev-parse", rs.def)
		if err != nil {
			rs.fpErr = err
			return
		}
		tip := strings.TrimSpace(tipOut)
		h.fpMu.Lock()
		c, ok := h.fingerprints[rs.ref.Common]
		h.fpMu.Unlock()
		if ok && c.tip == tip {
			rs.fp = c.ids
			return
		}
		rs.fp, rs.fpErr = defaultPatchIDs(ctx, rs.ref.Main, rs.def)
		if rs.fpErr == nil {
			h.fpMu.Lock()
			h.fingerprints[rs.ref.Common] = fingerprintCache{tip: tip, ids: rs.fp}
			h.fpMu.Unlock()
		}
	})
	return rs.fp, rs.fpErr
}

// inspectOne gathers one worktree's facts. The main worktree and missing
// directories are listed without inspection.
func (h *Hunter) inspectOne(ctx context.Context, rs *repoScan, isMain bool, l listed, activity []model.WorkspaceActivity) (Worktree, facts) {
	w := Worktree{Path: l.Path, Branch: l.Branch, Head: l.Head, Detached: l.Detached, Locked: l.Locked, LockReason: l.LockReason}
	f := facts{Main: isMain || l.Bare, DefaultBranch: rs.out.DefaultBranch}
	if f.Main {
		return w, f
	}
	if _, err := os.Stat(l.Path); err != nil || l.Prunable {
		f.Missing = true
		return w, f
	}

	w.InUse, w.ActiveAgent, f.LastSession = agentAt(l.Path, activity, h.now())
	f.HeadTime = headTime(ctx, l.Path)
	f.IndexTime = indexTime(l.Path)

	st, err := readStatus(ctx, l.Path)
	if err != nil {
		w.Error = err.Error()
		return w, f
	}
	w.Upstream, w.Ahead, w.Behind, w.UpstreamGone = st.Upstream, st.Ahead, st.Behind, st.UpstreamGone
	w.Changed, w.Untracked, w.Conflicts, w.Paths = st.Changed, st.Untracked, st.Conflicts, st.Paths
	w.PartlyStaged = st.PartlyStaged
	if w.Operation, err = gitOperation(ctx, l.Path); err != nil {
		w.Error = err.Error()
		return w, f
	}

	ign, err := readIgnored(ctx, l.Path)
	if err != nil {
		w.Error = err.Error()
		return w, f
	}
	w.PreciousIgnored, w.ScratchIgnored, w.OtherIgnored = ign.Precious, ign.Scratch, ign.Other

	subs, err := readSubmodules(ctx, l.Path)
	if err != nil {
		w.Error = err.Error()
		return w, f
	}
	w.Submodules, w.SubmoduleLocal = subs.Populated, subs.Local

	if l.Detached {
		if w.Loose, err = countCommits(ctx, l.Path, "HEAD", "--not", "--branches", "--tags", "--remotes"); err != nil {
			w.Error = err.Error()
			return w, f
		}
	} else {
		w.Stashes = rs.stashes[l.Branch]
	}
	uniqueArgs := []string{"HEAD", "--not", "--remotes"}
	if rs.def != "" {
		uniqueArgs = append(uniqueArgs, rs.def)
	}
	if w.Unique, err = countCommits(ctx, l.Path, uniqueArgs...); err != nil {
		w.Error = err.Error()
		return w, f
	}
	if rs.def != "" {
		m := h.mergeState(ctx, rs, l)
		w.Merged, w.Unrelated = m.state, m.unrelated
		w.ContentLines, w.ContentMissing, w.ContentExtended, w.ContentOther = m.lines, m.missing, m.extended, m.other
	}
	return w, f
}

// mergeState checks ancestry and patch equivalence against the default branch.
// Its content fallback reports unordered line similarity for review only. The
// squash check needs a merge-base at most squashDepth commits back; the
// content check also runs from the branch's creation point when the default
// branch was rewritten and shares no history with it.
func (h *Hunter) mergeState(ctx context.Context, rs *repoScan, l listed) mergeVerdict {
	unknown := mergeVerdict{state: mergedUnknown}
	dir := l.Path
	anc, err := gitOK(ctx, dir, "merge-base", "--is-ancestor", "HEAD", rs.def)
	if err != nil {
		return unknown
	}
	if anc {
		return mergeVerdict{state: mergedAncestor}
	}
	base, viaMergeBase, err := forkBase(ctx, dir, l.Branch, rs.def)
	if err != nil {
		return unknown
	}
	if base == "" {
		return mergeVerdict{state: mergedUnknown, unrelated: true}
	}
	squashSaidNo := false
	if viaMergeBase {
		behind, err := countCommits(ctx, dir, "--no-merges", base+".."+rs.def)
		if err != nil {
			return unknown
		}
		if behind <= squashDepth {
			id, err := branchPatchID(ctx, dir, base)
			if err != nil {
				return unknown
			}
			if id == "" {
				return mergeVerdict{state: mergedEmpty}
			}
			fp, err := h.repoFingerprints(ctx, rs)
			if err != nil {
				return unknown
			}
			if fp[id] {
				return mergeVerdict{state: mergedSquash}
			}
			squashSaidNo = true
		}
	}
	v := h.contentCheck(ctx, rs, dir, base)
	v.unrelated = !viaMergeBase
	// A diff too big to measure by content keeps the squash check's answer.
	if v.state == mergedUnknown && squashSaidNo {
		v.state = mergedNo
	}
	return v
}

// dropBare removes the bare repository's own entry: it has no working
// directory to judge.
func dropBare(r RepoReport) RepoReport {
	if !r.Bare || len(r.Worktrees) == 0 {
		return r
	}
	r.Worktrees = r.Worktrees[1:]
	return r
}

// attachOrphans files each orphan directory under the repository its dead
// gitdir pointed into, creating a group when that repo was not found.
func attachOrphans(repos []RepoReport, orphans []orphanDir, activity []model.WorkspaceActivity, now time.Time, staleAfter time.Duration) []RepoReport {
	for _, o := range orphans {
		w := Worktree{Path: o.Path, Orphan: true}
		f := facts{IndexTime: dirTime(o.Path)}
		w.InUse, w.ActiveAgent, f.LastSession = agentAt(o.Path, activity, now)
		classify(&w, f, now, staleAfter)
		i := -1
		for k := range repos {
			if repos[k].Path == o.Main {
				i = k
				break
			}
		}
		if c := reconnectCandidate(repos, o); c != "" {
			w.Reconnect = c
			w.reason(ReasonInfo, c+" still records this worktree: Reconnect links it again")
		}
		if i < 0 {
			name := o.Main
			if name == "" {
				name = filepath.Dir(o.Path)
			}
			repos = append(repos, RepoReport{Path: name, Error: ErrRepoMissing})
			i = len(repos) - 1
		}
		repos[i].Worktrees = append(repos[i].Worktrees, w)
	}
	return repos
}

// agentAt reads the sessions working in dir or under it at now: whether any
// is active (model.WorkspaceActivity.ActiveAt), the harness of the one to
// name (a live session before an ended one, then the newest), and the newest
// last_seen among all of them.
func agentAt(dir string, activity []model.WorkspaceActivity, now time.Time) (inUse bool, agent string, lastSeen time.Time) {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	var named model.WorkspaceActivity
	for _, a := range activity {
		if a.Workspace != dir && !strings.HasPrefix(a.Workspace, prefix) {
			continue
		}
		if a.LastSeen.After(lastSeen) {
			lastSeen = a.LastSeen
		}
		if !a.ActiveAt(now) {
			continue
		}
		inUse = true
		if a.Harness != "" && (named.Harness == "" || (a.Live && !named.Live) ||
			(a.Live == named.Live && a.LastSeen.After(named.LastSeen))) {
			named = a
		}
	}
	return inUse, named.Harness, lastSeen
}

func dirTime(p string) time.Time {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime().UTC()
}

func summarize(repos []RepoReport) ScanSummary {
	s := ScanSummary{Repos: len(repos)}
	for _, r := range repos {
		for _, w := range r.Worktrees {
			if w.State == StateMain {
				continue
			}
			s.Worktrees++
			switch w.State {
			case StateRemove:
				s.Remove++
			case StateReview:
				s.Review++
			case StateKeep:
				s.Keep++
			case StatePrune:
				s.Prune++
			}
			if w.Stale {
				s.Stale++
			}
		}
	}
	return s
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
