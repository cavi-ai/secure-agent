package worktreehunter

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
)

// sizeTTL is how long a measured size answers without a new walk; an older
// size still answers while the sizer measures it again.
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

// cachedSize returns the last measurement of path and whether it is older
// than sizeTTL.
func (h *Hunter) cachedSize(path string) (sizeEntry, bool, bool) {
	h.sizeMu.Lock()
	defer h.sizeMu.Unlock()
	e, ok := h.sizes[path]
	return e, ok && h.now().Sub(e.at) > sizeTTL, ok
}

// saveSizes stores the measured sizes.
func (h *Hunter) saveSizes() {
	h.sizeMu.Lock()
	saved := make(map[string]savedSize, len(h.sizes))
	for p, e := range h.sizes {
		saved[p] = savedSize{Bytes: e.bytes, Partial: e.partial, At: e.at}
	}
	h.sizeMu.Unlock()
	if body, err := json.Marshal(saved); err == nil {
		h.st.PutScanCache(cacheSizesKey, body, h.now())
	}
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
		h.saveSizes()
	}()
}

// withSizes deep-copies rep (the cached scan stays untouched) and fills
// each measurable row's size, the repository and summary totals and the
// volumes; rows never measured, or measured more than sizeTTL ago, are
// queued for the sizer. An old size answers until the new one lands.
func (h *Hunter) withSizes(rep ScanReport) ScanReport {
	repos := make([]RepoReport, len(rep.Repos))
	var jobs []sizeJob
	missing := 0
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
			e, old, ok := h.cachedSize(w.Path)
			if ok {
				w.SizeBytes, w.SizePartial = e.bytes, e.partial
				r.SizeBytes += e.bytes
				rep.Summary.SizeBytes += e.bytes
				if w.State == StateRemove {
					rep.Summary.RemovableBytes += e.bytes
				}
				if !old {
					continue
				}
			} else {
				missing++
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
	rep.Sizing = missing > 0
	rep.Refreshing = rep.Refreshing || len(jobs) > missing
	rep.Volumes = diskusage.Volumes(roots)
	h.startSizing(jobs)
	return rep
}
