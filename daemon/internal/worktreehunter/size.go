package worktreehunter

import (
	"context"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
)

// sizeTTL is how long a measured size answers without a new walk.
const sizeTTL = time.Hour

// sizeEntry is one cached measurement.
type sizeEntry struct {
	bytes   int64
	partial bool
	at      time.Time
}

// sizeJob is one worktree the sizer measures, with the other worktrees of
// its repository to leave out of the walk.
type sizeJob struct {
	path string
	skip map[string]bool
}

// sizerWorkers bounds concurrent directory walks: sizing is disk-bound and
// must not starve the daemon.
const sizerWorkers = 2

// cachedSize returns a measurement younger than sizeTTL.
func (h *Hunter) cachedSize(path string) (sizeEntry, bool) {
	h.sizeMu.Lock()
	defer h.sizeMu.Unlock()
	e, ok := h.sizes[path]
	if !ok || h.now().Sub(e.at) > sizeTTL {
		return sizeEntry{}, false
	}
	return e, true
}

func (h *Hunter) forgetSize(path string) {
	h.sizeMu.Lock()
	defer h.sizeMu.Unlock()
	delete(h.sizes, path)
}

// startSizing measures jobs in the background unless a pass is running.
// Detached from any request: the next report picks the sizes up.
func (h *Hunter) startSizing(jobs []sizeJob) {
	h.sizeMu.Lock()
	if h.sizing || len(jobs) == 0 {
		h.sizeMu.Unlock()
		return
	}
	h.sizing = true
	h.sizeWG.Add(1)
	h.sizeMu.Unlock()
	go func() {
		defer h.sizeWG.Done()
		defer func() {
			h.sizeMu.Lock()
			h.sizing = false
			h.sizeMu.Unlock()
		}()
		ch := make(chan sizeJob)
		var wg sync.WaitGroup
		for i := 0; i < sizerWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range ch {
					u := diskusage.Dir(context.Background(), j.path, j.skip)
					h.sizeMu.Lock()
					h.sizes[j.path] = sizeEntry{bytes: u.Bytes, partial: u.Partial, at: h.now()}
					h.sizeMu.Unlock()
				}
			}()
		}
		for _, j := range jobs {
			ch <- j
		}
		close(ch)
		wg.Wait()
	}()
}

// withSizes deep-copies rep (the cached scan stays untouched) and fills
// each measurable row's size, the repository and summary totals and the
// volumes; rows without a fresh size are queued for the sizer.
func (h *Hunter) withSizes(rep ScanReport) ScanReport {
	repos := make([]RepoReport, len(rep.Repos))
	var jobs []sizeJob
	var roots []string
	rep.Summary.SizeBytes, rep.Summary.RemovableBytes = 0, 0
	for i, r := range rep.Repos {
		r.Worktrees = append([]Worktree(nil), r.Worktrees...)
		r.SizeBytes = 0
		all := map[string]bool{}
		for _, w := range r.Worktrees {
			all[w.Path] = true
		}
		for j := range r.Worktrees {
			w := &r.Worktrees[j]
			if w.State == StateMain || w.State == StatePrune {
				continue
			}
			if e, ok := h.cachedSize(w.Path); ok {
				w.SizeBytes, w.SizePartial = e.bytes, e.partial
				r.SizeBytes += e.bytes
				rep.Summary.SizeBytes += e.bytes
				if w.State == StateRemove {
					rep.Summary.RemovableBytes += e.bytes
				}
				continue
			}
			skip := map[string]bool{}
			for p := range all {
				if p != w.Path {
					skip[p] = true
				}
			}
			jobs = append(jobs, sizeJob{path: w.Path, skip: skip})
		}
		if r.Error == "" {
			roots = append(roots, r.Path)
		}
		repos[i] = r
	}
	rep.Repos = repos
	rep.Sizing = len(jobs) > 0
	rep.Volumes = diskusage.Volumes(roots)
	h.startSizing(jobs)
	return rep
}
