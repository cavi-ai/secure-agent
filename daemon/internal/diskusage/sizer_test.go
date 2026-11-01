package diskusage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func testSizer(now *time.Time) *sizer {
	return newSizer(MeasureWorkers, func() time.Time { return *now })
}

// A walk of a worktree records its node_modules, and a Measure of that
// node_modules within ReuseWindow answers from it without walking.
func TestMeasureReusesATrackedSubtreeOfAnEnclosingWalk(t *testing.T) {
	now := time.Now()
	s := testSizer(&now)
	s.trackNames("node_modules")
	root := t.TempDir()
	write(t, filepath.Join(root, "main.go"), 1000)
	nm := filepath.Join(root, "node_modules")
	write(t, filepath.Join(nm, "pkg", "index.js"), 20000)

	whole := s.measure(context.Background(), root, nil, MaxEntries)
	alone := Dir(context.Background(), nm, nil)
	write(t, filepath.Join(nm, "pkg", "added.js"), 30000) // not seen if reused

	got := s.measure(context.Background(), nm, nil, MaxEntries)
	if got.Bytes != alone.Bytes || got.Files != alone.Files || whole.Files != alone.Files+1 {
		t.Fatalf("reused node_modules = %+v, want the enclosing walk's %+v (whole %+v)", got, alone, whole)
	}
	now = now.Add(ReuseWindow)
	if got := s.measure(context.Background(), nm, nil, MaxEntries); got.Files != alone.Files+1 {
		t.Fatalf("past ReuseWindow node_modules = %+v, want a new walk with the added file", got)
	}
}

// A walk adds a subdirectory measured within ReuseWindow instead of walking
// it; measuring the same tree again always walks it.
func TestMeasureAddsARecentSubdirectoryMeasurement(t *testing.T) {
	now := time.Now()
	s := testSizer(&now)
	root := t.TempDir()
	write(t, filepath.Join(root, "a.bin"), 1000)
	build := filepath.Join(root, "build")
	write(t, filepath.Join(build, "out.bin"), 20000)

	first := s.measure(context.Background(), build, nil, MaxEntries)
	write(t, filepath.Join(build, "late.bin"), 30000)
	if again := s.measure(context.Background(), build, nil, MaxEntries); again.Files != first.Files+1 {
		t.Fatalf("measuring a tree again = %+v, want a walk that sees the added file (first %+v)", again, first)
	}
	write(t, filepath.Join(build, "later.bin"), 30000)
	whole := s.measure(context.Background(), root, nil, MaxEntries)
	if whole.Files != first.Files+2 {
		t.Fatalf("enclosing walk = %+v, want a.bin plus the recent build measurement (%d files)", whole, first.Files+1)
	}
}

// A measurement that left a skipped tree out is neither recorded for the
// tree it covers nor added in place of a walk that skips inside it.
func TestMeasureDoesNotReuseAcrossSkippedTrees(t *testing.T) {
	now := time.Now()
	s := testSizer(&now)
	s.trackNames("node_modules")
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	nested := filepath.Join(nm, "nested-worktree")
	write(t, filepath.Join(nm, "pkg.js"), 1000)
	write(t, filepath.Join(nested, "big.bin"), 50000)

	s.measure(context.Background(), root, map[string]bool{nested: true}, MaxEntries)
	if got := s.measure(context.Background(), nm, nil, MaxEntries); got.Files != 2 {
		t.Fatalf("node_modules = %+v, want a full walk: the enclosing walk skipped a tree inside it", got)
	}
	if got := s.measure(context.Background(), root, map[string]bool{nested: true}, MaxEntries); got.Files != 1 {
		t.Fatalf("root skipping the nested tree = %+v, want the recent node_modules measurement left unused", got)
	}
}

// A walk cut short records no subtree it did not finish; Forget drops a tree
// and everything recorded inside it.
func TestMeasurePartialWalksAndForget(t *testing.T) {
	now := time.Now()
	s := testSizer(&now)
	s.trackNames("node_modules")
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	for _, f := range []string{"a.js", "b.js", "c.js", "d.js"} {
		write(t, filepath.Join(nm, f), 1000)
	}
	if u := s.measure(context.Background(), root, nil, 4); !u.Partial {
		t.Fatal("a walk past its entry bound must be partial")
	}
	if _, ok := s.known[nm]; ok {
		t.Fatal("recorded a subtree the walk did not finish")
	}
	s.measure(context.Background(), root, nil, MaxEntries)
	if _, ok := s.known[nm]; !ok {
		t.Fatal("a finished walk must record the tracked subtree")
	}
	s.forget(root)
	if len(s.known) != 0 {
		t.Fatalf("Forget left %v", s.known)
	}
}

// A caller whose context ends while every walk slot is taken gets a partial
// result without walking.
func TestMeasureWaitsForAWalkSlot(t *testing.T) {
	now := time.Now()
	s := testSizer(&now)
	for i := 0; i < MeasureWorkers; i++ {
		s.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if u := s.measure(ctx, t.TempDir(), nil, MaxEntries); !u.Partial || u.Files != 0 {
		t.Fatalf("measure without a slot = %+v", u)
	}
}
