package worktreehunter

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
