package worktreehunter

import (
	"context"
	"io/fs"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// sizeTimeout bounds one directory walk; a walk that hits it (or
	// maxSizeEntries) reports a partial, lower-bound size.
	sizeTimeout = 30 * time.Second
	// sizeTTL is how long a measured size answers without a new walk.
	sizeTTL = time.Hour
)

// maxSizeEntries bounds the entries one walk visits (a var for tests).
var maxSizeEntries = 1_000_000

// dirSize sums the allocated bytes (st_blocks × 512) of every file under
// root: the space removal gives back. It never follows symlinks and does not
// descend into skip (other worktrees nested inside this one). partial is
// true when the walk stopped at a bound or ctx ended.
func dirSize(ctx context.Context, root string, skip map[string]bool) (bytes int64, partial bool) {
	ctx, cancel := context.WithTimeout(ctx, sizeTimeout)
	defer cancel()
	entries := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		entries++
		if entries > maxSizeEntries || (entries%4096 == 0 && ctx.Err() != nil) {
			partial = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p != root && skip[p] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			bytes += st.Blocks * 512
		} else {
			bytes += info.Size()
		}
		return nil
	})
	return bytes, partial
}

// sizeEntry is one cached measurement.
type sizeEntry struct {
	bytes   int64
	partial bool
	at      time.Time
}

// VolumeUsage is one mounted volume holding scanned repositories.
type VolumeUsage struct {
	Mount      string `json:"mount"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

// volumeUsage groups paths by volume (filesystem id) and reads each one's
// capacity and free space once.
func volumeUsage(paths []string) []VolumeUsage {
	seen := map[[2]int32]int{}
	var out []VolumeUsage
	for _, p := range paths {
		var st unix.Statfs_t
		if unix.Statfs(p, &st) != nil {
			continue
		}
		key := [2]int32{int32(st.Fsid.Val[0]), int32(st.Fsid.Val[1])}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = len(out)
		mount := mountPoint(&st)
		if mount == "" {
			mount = volumeRoot(p)
		}
		out = append(out, VolumeUsage{
			Mount:      mount,
			TotalBytes: uint64(st.Blocks) * uint64(st.Bsize),
			FreeBytes:  uint64(st.Bavail) * uint64(st.Bsize),
		})
	}
	return mergeShared(out)
}

// mergeShared folds volumes that report the same capacity and free space
// into one row: APFS volumes in one container share both, and listing them
// separately reads as two disks.
func mergeShared(vs []VolumeUsage) []VolumeUsage {
	var out []VolumeUsage
	for _, v := range vs {
		merged := false
		for i := range out {
			if out[i].TotalBytes == v.TotalBytes && out[i].FreeBytes == v.FreeBytes {
				out[i].Mount += " + " + v.Mount
				merged = true
				break
			}
		}
		if !merged {
			out = append(out, v)
		}
	}
	return out
}

// volumeRoot walks up from p while the device stays the same.
func volumeRoot(p string) string {
	var st unix.Stat_t
	if unix.Stat(p, &st) != nil {
		return p
	}
	dev := st.Dev
	for {
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		if unix.Stat(parent, &st) != nil || st.Dev != dev {
			return p
		}
		p = parent
	}
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
					b, partial := dirSize(context.Background(), j.path, j.skip)
					h.sizeMu.Lock()
					h.sizes[j.path] = sizeEntry{bytes: b, partial: partial, at: h.now()}
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
	rep.Volumes = volumeUsage(roots)
	h.startSizing(jobs)
	return rep
}
