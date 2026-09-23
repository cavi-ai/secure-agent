// Package worktreehunter is the worktree hunter: it finds every git worktree on
// the machine (from agent session workspaces, the directories agent apps keep
// worktrees in, configured scan roots and a saved repo list), inspects each
// one read-only, and says whether it can be removed and why.
//
// Invariants:
//   - Read-only toward the repositories: GIT_OPTIONAL_LOCKS=0, no fetch, no
//     object writes, no network. Merge detection is local (ancestry, then a
//     patch-id match for squash merges).
//   - Scans run on request, one at a time, with a cached result; no
//     background loop.
//   - The verdict is deterministic (classify). Nothing outside the facts
//     can turn keep into remove.
package worktreehunter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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
}

// Options are the operator's knobs (config `worktrees:`).
type Options struct {
	Roots     []string
	StaleDays int
}

const (
	// DefaultStaleDays is the idle age that marks a worktree stale.
	DefaultStaleDays = 14
	// cacheTTL is how long a scan answers GET without rescanning.
	cacheTTL = 10 * time.Minute
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
}

// RepoReport groups one repository's worktrees; the main worktree comes first.
type RepoReport struct {
	Path          string     `json:"path"`
	Source        string     `json:"source,omitempty"`
	DefaultBranch string     `json:"default_branch,omitempty"`
	Bare          bool       `json:"bare,omitempty"`
	Worktrees     []Worktree `json:"worktrees"`
	Error         string     `json:"error,omitempty"`
}

// Hunter owns scans and their cache.
type Hunter struct {
	st   Store
	home string
	now  func() time.Time

	mu       sync.Mutex
	opts     Options
	cached   *ScanReport
	cachedAt time.Time

	// scanMu serializes scans; a request that waited on it reuses the scan
	// that finished meanwhile.
	scanMu sync.Mutex

	fpMu sync.Mutex
	// fingerprints caches each repository's default-branch patch ids by
	// the branch tip they were computed at.
	fingerprints map[string]fingerprintCache
}

type fingerprintCache struct {
	tip string
	ids map[string]bool
}

// New builds a hunter. home "" resolves to the user's home directory.
func New(st Store, home string, opts Options) *Hunter {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return &Hunter{st: st, home: home, now: time.Now, opts: normalize(opts), fingerprints: map[string]fingerprintCache{}}
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
	h.cached = nil
}

// Options returns the options in effect.
func (h *Hunter) Options() Options {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opts
}

func (h *Hunter) invalidate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cached = nil
}

// Report returns the cached scan when it is younger than cacheTTL and
// refresh is false; otherwise it scans. The scan runs under its own
// deadline, detached from ctx's cancellation, so a client that gives up
// still leaves a finished report for the next request.
func (h *Hunter) Report(ctx context.Context, refresh bool) ScanReport {
	asked := h.now()
	if r, ok := h.fresh(refresh, time.Time{}); ok {
		return r
	}
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	if r, ok := h.fresh(refresh, asked); ok {
		return r
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), scanTimeout)
	defer cancel()
	h.mu.Lock()
	opts := h.opts
	h.mu.Unlock()
	rep := h.scan(sctx, opts)
	h.mu.Lock()
	h.cached, h.cachedAt = &rep, h.now()
	h.mu.Unlock()
	return rep
}

// fresh returns the cached report when it may answer: younger than cacheTTL
// (minRescan when a refresh is asked), or finished after `after` (a scan
// that completed while this request waited answers even a refresh).
func (h *Hunter) fresh(refresh bool, after time.Time) (ScanReport, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached == nil {
		return ScanReport{}, false
	}
	maxAge := cacheTTL
	if refresh {
		maxAge = minRescan
	}
	if (!after.IsZero() && h.cachedAt.After(after)) || h.now().Sub(h.cachedAt) < maxAge {
		r := *h.cached
		r.Cached = true
		return r, true
	}
	return ScanReport{}, false
}

// ErrNotRepo is returned for a path that is not inside a git repository.
var ErrNotRepo = errors.New("not inside a git repository")

// AddRepo puts the repository containing path on the saved list as manual
// (unhiding it if hidden) and returns its main worktree path.
func (h *Hunter) AddRepo(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	ref, _, ok := resolveRepo(path)
	if !ok {
		return "", ErrNotRepo
	}
	h.st.UpsertWorktreeRepo(ref.Main, model.RepoSourceManual, h.now())
	h.invalidate()
	return ref.Main, nil
}

// HideRepo hides a saved repository from reports. path may be any
// directory inside it. Reports whether the repo was on the list.
func (h *Hunter) HideRepo(path string) bool {
	key := canonical(path)
	if ref, _, ok := resolveRepo(path); ok {
		key = ref.Main
	}
	ok := h.st.SetWorktreeRepoHidden(key, true)
	h.invalidate()
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
	rep.Repos = attachOrphans(rep.Repos, d.Orphans, now, staleAfter)
	sort.Slice(rep.Repos, func(i, j int) bool { return rep.Repos[i].Path < rep.Repos[j].Path })
	for _, r := range rep.Repos {
		if r.Error != "" {
			rep.Errors = append(rep.Errors, r.Path+": "+r.Error)
		}
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
	w := Worktree{Path: l.Path, Branch: l.Branch, Head: shortSHA(l.Head), Detached: l.Detached, Locked: l.Locked, LockReason: l.LockReason}
	f := facts{Main: isMain || l.Bare, DefaultBranch: rs.out.DefaultBranch}
	if f.Main {
		return w, f
	}
	if _, err := os.Stat(l.Path); err != nil || l.Prunable {
		f.Missing = true
		return w, f
	}

	prefix := strings.TrimSuffix(l.Path, "/") + "/"
	for _, a := range activity {
		if a.Workspace == l.Path || strings.HasPrefix(a.Workspace, prefix) {
			if a.LastSeen.After(f.LastSession) {
				f.LastSession = a.LastSeen
			}
			w.InUse = w.InUse || a.Live
		}
	}
	f.HeadTime = headTime(ctx, l.Path)
	f.IndexTime = indexTime(l.Path)

	st, err := readStatus(ctx, l.Path)
	if err != nil {
		w.Error = err.Error()
		return w, f
	}
	w.Upstream, w.Ahead, w.Behind, w.UpstreamGone = st.Upstream, st.Ahead, st.Behind, st.UpstreamGone
	w.Changed, w.Untracked, w.Conflicts, w.Paths = st.Changed, st.Untracked, st.Conflicts, st.Paths

	ign, err := readIgnored(ctx, l.Path)
	if err != nil {
		w.Error = err.Error()
		return w, f
	}
	w.PreciousIgnored, w.OtherIgnored = ign.Precious, ign.Other

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
		w.Merged = h.mergeState(ctx, rs, l.Path)
	}
	return w, f
}

// mergeState answers whether HEAD's work is already in the default branch:
// by ancestry, or as a squash commit carrying the branch's combined diff.
func (h *Hunter) mergeState(ctx context.Context, rs *repoScan, dir string) string {
	anc, err := gitOK(ctx, dir, "merge-base", "--is-ancestor", "HEAD", rs.def)
	if err != nil {
		return mergedUnknown
	}
	if anc {
		return mergedAncestor
	}
	mbOut, err := git(ctx, dir, "merge-base", "HEAD", rs.def)
	if err != nil {
		return mergedUnknown
	}
	mb := strings.TrimSpace(mbOut)
	behind, err := countCommits(ctx, dir, "--no-merges", mb+".."+rs.def)
	if err != nil || behind > squashDepth {
		return mergedUnknown
	}
	id, err := branchPatchID(ctx, dir, mb)
	if err != nil {
		return mergedUnknown
	}
	if id == "" {
		return mergedEmpty
	}
	fp, err := h.repoFingerprints(ctx, rs)
	if err != nil {
		return mergedUnknown
	}
	if fp[id] {
		return mergedSquash
	}
	return mergedNo
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
func attachOrphans(repos []RepoReport, orphans []orphanDir, now time.Time, staleAfter time.Duration) []RepoReport {
	for _, o := range orphans {
		w := Worktree{Path: o.Path, Orphan: true}
		classify(&w, facts{IndexTime: dirTime(o.Path)}, now, staleAfter)
		i := -1
		for k := range repos {
			if repos[k].Path == o.Main {
				i = k
				break
			}
		}
		if i < 0 {
			name := o.Main
			if name == "" {
				name = filepath.Dir(o.Path)
			}
			repos = append(repos, RepoReport{Path: name, Error: "repository not found"})
			i = len(repos) - 1
		}
		repos[i].Worktrees = append(repos[i].Worktrees, w)
	}
	return repos
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
