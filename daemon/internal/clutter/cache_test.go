package clutter

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
)

// A restarted daemon answers from the saved inventory and sizes at once,
// then rebuilds in the background once the saved inventory is older than
// cacheTTL.
func TestSavedInventoryAndSizesAnswerAfterRestart(t *testing.T) {
	m := newMachine(t)
	st := &memStore{}
	now := time.Now()
	first := m.clutter(st)
	first.now = func() time.Time { return now }
	first.Report(context.Background(), true)
	first.sizeWG.Wait()
	tmp := filepath.Join(m.repo, ".tmp")
	if err := os.RemoveAll(tmp); err != nil {
		t.Fatal(err)
	}

	restarted := m.clutter(st)
	restarted.now = func() time.Time { return now }
	rep := restarted.Report(context.Background(), false)
	if it := byPath(t, rep, tmp); it.SizeBytes < 3000 || rep.Sizing || rep.Refreshing {
		t.Fatalf("restart must answer from the saved inventory: size %d sizing=%v refreshing=%v", it.SizeBytes, rep.Sizing, rep.Refreshing)
	}

	now = now.Add(cacheTTL + time.Second)
	if rep := restarted.Report(context.Background(), false); !rep.Refreshing {
		t.Fatal("an expired saved inventory must answer while a rebuild runs")
	}
	restarted.bgWG.Wait()
	for _, it := range restarted.Report(context.Background(), false).Items {
		if it.Path == tmp {
			t.Fatal("the background rebuild still lists the removed .tmp")
		}
	}
}

// A size older than sizeTTL keeps answering while the sizer measures again.
func TestOldClutterSizeAnswersWhileRemeasured(t *testing.T) {
	m := newMachine(t)
	now := time.Now()
	c := m.clutter(&memStore{})
	c.now = func() time.Time { return now }
	tmp := filepath.Join(m.repo, ".tmp")
	c.Report(context.Background(), true)
	c.sizeWG.Wait()
	before := byPath(t, c.Report(context.Background(), false), tmp).SizeBytes
	mk(t, filepath.Join(tmp, "more.log"), 90000)

	now = now.Add(sizeTTL + time.Second)
	rep := c.Report(context.Background(), true)
	if got := byPath(t, rep, tmp).SizeBytes; got != before || rep.Sizing || !rep.Refreshing {
		t.Fatalf("while re-measuring: size %d (want the old %d), sizing=%v refreshing=%v", got, before, rep.Sizing, rep.Refreshing)
	}
	c.sizeWG.Wait()
	rep = c.Report(context.Background(), false)
	if got := byPath(t, rep, tmp).SizeBytes; got < before+90000 || rep.Refreshing {
		t.Fatalf("after re-measuring: size %d (was %d), refreshing=%v", got, before, rep.Refreshing)
	}
}

// Sizes answer for sizeTTL; an asked refresh measures again the ones older
// than diskusage.ReuseWindow.
func TestAskedRefreshRemeasuresRecentClutterSizes(t *testing.T) {
	m := newMachine(t)
	now := time.Now()
	var mu sync.Mutex
	c := m.clutter(&memStore{})
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	tmp := filepath.Join(m.repo, ".tmp")
	c.Report(context.Background(), true)
	c.sizeWG.Wait()
	before := byPath(t, c.Report(context.Background(), false), tmp).SizeBytes
	mk(t, filepath.Join(tmp, "more.log"), 90000)
	mu.Lock()
	now = now.Add(diskusage.ReuseWindow + time.Second)
	mu.Unlock()

	c.Report(context.Background(), false)
	c.sizeWG.Wait()
	c.bgWG.Wait()
	if got := byPath(t, c.Report(context.Background(), false), tmp).SizeBytes; got != before {
		t.Fatalf("an unasked report re-measured a size within sizeTTL: %d, was %d", got, before)
	}
	c.Report(context.Background(), true)
	c.sizeWG.Wait()
	if got := byPath(t, c.Report(context.Background(), false), tmp).SizeBytes; got < before+90000 {
		t.Fatalf("after an asked refresh: size %d, want the added file counted (was %d)", got, before)
	}
}
