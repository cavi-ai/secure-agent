package worktreehunter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// A restarted daemon answers from the saved scan and sizes at once, then
// rescans in the background once the saved scan is older than cacheTTL.
func TestSavedScanAndSizesAnswerAfterRestart(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	done := f.worktree(t, "done")
	write(t, filepath.Join(done, "node_modules", "pkg", "big.js"), string(make([]byte, 40000)))
	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	now := time.Now()
	clock := func() time.Time { return now }

	first := New(st, home, Options{})
	first.now = clock
	first.Report(context.Background(), true)
	first.sizeWG.Wait()
	if err := os.RemoveAll(done); err != nil {
		t.Fatal(err)
	}

	restarted := New(st, home, Options{})
	restarted.now = clock
	rep := restarted.Report(context.Background(), false)
	row := findRow(t, rep, done)
	if !rep.Cached || rep.Refreshing || rep.Sizing || row.State == StatePrune || row.SizeBytes < 40000 {
		t.Fatalf("restart must answer from the saved scan: cached=%v refreshing=%v sizing=%v state=%s size=%d",
			rep.Cached, rep.Refreshing, rep.Sizing, row.State, row.SizeBytes)
	}

	now = now.Add(cacheTTL + time.Second)
	if rep := restarted.Report(context.Background(), false); !rep.Refreshing {
		t.Fatal("an expired saved scan must answer while a rescan runs")
	}
	restarted.bgWG.Wait()
	if row := findRow(t, restarted.Report(context.Background(), false), done); row.State != StatePrune {
		t.Fatalf("the background rescan did not see the removed worktree: %s", row.State)
	}

	other := New(st, home, Options{StaleDays: 30})
	other.now = clock
	if rep := other.Report(context.Background(), false); rep.Cached {
		t.Fatal("a scan saved under other options answered")
	}
}

// A saved scan whose rows lack a kind per reason is not served; the restarted
// daemon scans again.
func TestSavedScanWithoutReasonKindsIsRescanned(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	f.worktree(t, "done")
	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	first := New(st, home, Options{})
	first.Report(context.Background(), true)
	first.sizeWG.Wait()

	body, at, ok := st.ScanCache(cacheReportKey)
	if !ok {
		t.Fatal("first scan saved nothing")
	}
	var saved savedReport
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	for i := range saved.Report.Repos {
		for j := range saved.Report.Repos[i].Worktrees {
			saved.Report.Repos[i].Worktrees[j].ReasonKinds = nil
		}
	}
	old, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	st.PutScanCache(cacheReportKey, old, at)

	rep := New(st, home, Options{}).Report(context.Background(), false)
	if rep.Cached {
		t.Fatal("a saved scan without reason kinds answered")
	}
	for _, r := range rep.Repos {
		for _, w := range r.Worktrees {
			if len(w.ReasonKinds) != len(w.Reasons) {
				t.Fatalf("%s: kinds %q for reasons %q", w.Path, w.ReasonKinds, w.Reasons)
			}
		}
	}
}

// A size older than sizeTTL keeps answering while the sizer measures again.
func TestOldSizeAnswersWhileRemeasured(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	done := f.worktree(t, "done")
	write(t, filepath.Join(done, "node_modules", "pkg", "big.js"), string(make([]byte, 40000)))
	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	now := time.Now()
	h := New(st, home, Options{})
	h.now = func() time.Time { return now }

	h.Report(context.Background(), true)
	h.sizeWG.Wait()
	before := findRow(t, h.Report(context.Background(), false), done).SizeBytes
	write(t, filepath.Join(done, "node_modules", "pkg", "more.js"), string(make([]byte, 80000)))

	now = now.Add(sizeTTL + time.Second)
	rep := h.Report(context.Background(), true)
	if got := findRow(t, rep, done).SizeBytes; got != before || rep.Sizing || !rep.Refreshing {
		t.Fatalf("while re-measuring: size %d (want the old %d), sizing=%v refreshing=%v", got, before, rep.Sizing, rep.Refreshing)
	}
	h.sizeWG.Wait()
	rep = h.Report(context.Background(), false)
	if got := findRow(t, rep, done).SizeBytes; got < before+80000 || rep.Refreshing {
		t.Fatalf("after re-measuring: size %d (was %d), refreshing=%v", got, before, rep.Refreshing)
	}
}

// A pass saves its sizes as it measures them, at most every sizeSaveEvery,
// so a daemon restarted mid-pass keeps what it measured.
func TestSizerSavesSizesDuringThePass(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	f.worktree(t, "one")
	f.worktree(t, "two")
	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	var calls atomic.Int64
	base := time.Now()
	h := New(st, home, Options{})
	h.now = func() time.Time { return base.Add(time.Duration(calls.Add(1)) * sizeSaveEvery) }

	h.Report(context.Background(), true)
	h.sizeWG.Wait()
	st.mu.Lock()
	saves := st.puts[cacheSizesKey]
	st.mu.Unlock()
	if saves != 3 {
		t.Fatalf("size saves = %d, want one per measured worktree and one at the end of the pass", saves)
	}
}

// Sizes answer for sizeTTL; an asked refresh measures again the ones older
// than diskusage.ReuseWindow.
func TestAskedRefreshRemeasuresRecentSizes(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	done := f.worktree(t, "done")
	write(t, filepath.Join(done, "big.bin"), string(make([]byte, 40000)))
	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	now := time.Now()
	var mu sync.Mutex
	h := New(st, home, Options{})
	h.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }

	h.Report(context.Background(), true)
	h.sizeWG.Wait()
	before := findRow(t, h.Report(context.Background(), false), done).SizeBytes
	write(t, filepath.Join(done, "more.bin"), string(make([]byte, 80000)))
	mu.Lock()
	now = now.Add(diskusage.ReuseWindow + time.Second)
	mu.Unlock()

	h.Report(context.Background(), false)
	h.sizeWG.Wait()
	h.bgWG.Wait()
	if got := findRow(t, h.Report(context.Background(), false), done).SizeBytes; got != before {
		t.Fatalf("an unasked report re-measured a size within sizeTTL: %d, was %d", got, before)
	}
	h.Report(context.Background(), true)
	h.sizeWG.Wait()
	if got := findRow(t, h.Report(context.Background(), false), done).SizeBytes; got < before+80000 {
		t.Fatalf("after an asked refresh: size %d, want the added file counted (was %d)", got, before)
	}
}
