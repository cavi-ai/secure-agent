package diskusage

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Background size measurement is shared by every owner in the process (the
// worktree hunter and the cleanup inventory measure overlapping trees: a
// worktree and the node_modules inside it). Measure runs at most
// MeasureWorkers walks at a time, and a walk reuses what another walk just
// measured instead of walking it again.

// MeasureWorkers bounds concurrent Measure walks process-wide.
const MeasureWorkers = 2

// ReuseWindow is how long a measurement stands in for another walk of the
// same tree.
const ReuseWindow = 15 * time.Minute

// measured is one complete measurement. sub marks a subtree measured during
// a walk of an enclosing tree; only those answer a Measure of the tree
// itself, so a caller measuring a tree again always walks it.
type measured struct {
	u   Usage
	at  time.Time
	sub bool
}

type sizer struct {
	slots chan struct{}
	now   func() time.Time

	mu    sync.Mutex
	known map[string]measured
	track map[string]bool
}

var shared = newSizer(MeasureWorkers, time.Now)

func newSizer(workers int, now func() time.Time) *sizer {
	return &sizer{slots: make(chan struct{}, workers), now: now, known: map[string]measured{}, track: map[string]bool{}}
}

// Measure is Dir for background sizing: it waits for one of MeasureWorkers
// walk slots, answers from a subtree an enclosing walk measured within
// ReuseWindow, adds such recent measurements of subdirectories without
// walking them, and records the subtrees named by Track for other callers.
func Measure(ctx context.Context, root string, skip map[string]bool) Usage {
	return shared.measure(ctx, root, skip, MaxEntries)
}

// Track names directories whose subtrees every Measure walk records, so a
// later Measure of one of them reuses the walk that passed through it.
func Track(names ...string) { shared.trackNames(names...) }

// Forget drops what is known about path and every tree inside it: it was
// removed or changed.
func Forget(path string) { shared.forget(path) }

func (s *sizer) trackNames(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range names {
		s.track[n] = true
	}
}

func (s *sizer) forget(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range s.known {
		if p == path || strings.HasPrefix(p, path+"/") {
			delete(s.known, p)
		}
	}
}

// recent returns the measurements younger than ReuseWindow and the tracked
// names, dropping expired measurements.
func (s *sizer) recent() (map[string]measured, map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	known := make(map[string]measured, len(s.known))
	for p, m := range s.known {
		if now.Sub(m.at) >= ReuseWindow {
			delete(s.known, p)
			continue
		}
		known[p] = m
	}
	track := make(map[string]bool, len(s.track))
	for n := range s.track {
		track[n] = true
	}
	return known, track
}

func (s *sizer) measure(ctx context.Context, root string, skip map[string]bool, limit int) Usage {
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return Usage{Partial: true}
	}
	defer func() { <-s.slots }()
	known, track := s.recent()
	if m, ok := known[root]; ok && m.sub && !skipsInside(skip, root) {
		return m.u
	}
	u, subs := walkReusing(ctx, root, skip, limit, known, track)
	at := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, su := range subs {
		s.known[p] = measured{u: su, at: at, sub: true}
	}
	if !u.Partial && !skipsInside(skip, root) {
		s.known[root] = measured{u: u, at: at}
	}
	return u
}

// skipsInside reports whether skip names root or a tree inside it: a
// measurement that left those out is not the whole tree.
func skipsInside(skip map[string]bool, root string) bool {
	for p := range skip {
		if skip[p] && (p == root || strings.HasPrefix(p, root+"/")) {
			return true
		}
	}
	return false
}

// subtree accumulates one tracked directory during a walk.
type subtree struct {
	path    string
	prefix  string // path + "/"
	u       Usage
	partial bool // a skipped tree inside it was left out
}

// walkReusing is DirLimit that adds known measurements of subdirectories
// instead of walking them and returns the complete measurements of the
// outermost directories whose names are tracked.
func walkReusing(ctx context.Context, root string, skip map[string]bool, limit int, known map[string]measured, track map[string]bool) (Usage, map[string]Usage) {
	ctx, cancel := context.WithTimeout(ctx, WalkTimeout)
	defer cancel()
	var u Usage
	subs := map[string]Usage{}
	var cur *subtree
	leave := func(p string) {
		if cur != nil && !strings.HasPrefix(p, cur.prefix) {
			if !cur.partial {
				subs[cur.path] = cur.u
			}
			cur = nil
		}
	}
	add := func(x Usage) {
		u.Bytes += x.Bytes
		u.Files += x.Files
		if x.Newest.After(u.Newest) {
			u.Newest = x.Newest
		}
		if cur != nil {
			cur.u.Bytes += x.Bytes
			cur.u.Files += x.Files
			if x.Newest.After(cur.u.Newest) {
				cur.u.Newest = x.Newest
			}
		}
	}
	entries := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		leave(p)
		entries++
		if entries > limit || (entries%4096 == 0 && ctx.Err() != nil) {
			u.Partial = true
			return filepath.SkipAll
		}
		if d.IsDir() && p != root {
			if skip[p] {
				if cur != nil {
					cur.partial = true
				}
				return filepath.SkipDir
			}
			if m, ok := known[p]; ok && !skipsInside(skip, p) {
				add(m.u)
				return filepath.SkipDir
			}
			if cur == nil && track[d.Name()] {
				cur = &subtree{path: p, prefix: p + "/"}
			}
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if d.IsDir() {
			add(Usage{Newest: info.ModTime()})
			return nil
		}
		x := Usage{Files: 1, Newest: info.ModTime()}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			x.Bytes = st.Blocks * 512
		} else {
			x.Bytes = info.Size()
		}
		add(x)
		return nil
	})
	if cur != nil && !u.Partial && !cur.partial {
		subs[cur.path] = cur.u
	}
	return u, subs
}
