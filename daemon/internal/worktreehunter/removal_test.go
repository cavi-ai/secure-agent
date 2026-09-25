package worktreehunter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func removalFixture(t *testing.T) (*Hunter, fixture) {
	t.Helper()
	home := isolateGit(t)
	f := newFixture(t)
	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	h := New(st, home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	return h, f
}

// Deleting a large tree takes longer than a read-only git call may: the
// removal runs under its own deadline, so git is not killed mid-delete.
func TestRemovalOutlastsTheReadTimeout(t *testing.T) {
	h, f := removalFixture(t)
	big := f.worktree(t, "big")
	for i := 0; i < 200; i++ {
		dir := filepath.Join(big, "node_modules", fmt.Sprintf("p%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 150; j++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.js", j)), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := gitTimeout
	gitTimeout = 400 * time.Millisecond
	t.Cleanup(func() { gitTimeout = old })

	if _, err := h.Remove(context.Background(), big); err != nil || exists(big) {
		t.Fatalf("Remove(30,000 files) = %v, still on disk %v", err, exists(big))
	}
}

// A canceled request does not stop a removal halfway.
func TestRemovalFinishesAfterTheRequestIsCanceled(t *testing.T) {
	h, f := removalFixture(t)
	wt := f.worktree(t, "done")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Remove(ctx, wt); err != nil || exists(wt) {
		t.Fatalf("Remove with a canceled request = %v, still on disk %v", err, exists(wt))
	}
}

// StartRemove answers at once; Removals reports the step while it waits
// and the outcome after, and a second start while one runs is refused.
func TestStartRemoveReportsStepsAndOutcome(t *testing.T) {
	h, f := removalFixture(t)
	done := f.worktree(t, "done")
	dirty := f.worktree(t, "dirty")
	write(t, filepath.Join(dirty, "base.txt"), "edited\n")

	if _, err := h.StartRemove("relative"); err == nil {
		t.Fatal("relative path accepted")
	}
	h.scanMu.Lock()
	rm, err := h.StartRemove(done)
	if err != nil || rm.State != RemovalRunning || rm.Path != done {
		t.Fatalf("StartRemove = %+v, %v", rm, err)
	}
	if _, err := h.StartRemove(done); !errors.Is(err, ErrRemoving) {
		t.Fatalf("second StartRemove while running: %v, want ErrRemoving", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.Removals()[done].Step != StepWaiting {
		if time.Now().After(deadline) {
			t.Fatalf("step = %q, want %q", h.Removals()[done].Step, StepWaiting)
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.scanMu.Unlock()
	if _, err := h.StartRemove(dirty); err != nil {
		t.Fatal(err)
	}
	h.remWG.Wait()

	all := h.Removals()
	if got := all[done]; got.State != RemovalRemoved || got.Step != "" || got.Branch != "feat/done" || got.FinishedAt == nil || exists(done) {
		t.Fatalf("done removal = %+v", got)
	}
	if got := all[dirty]; got.State != RemovalFailed || got.RowState != StateKeep || len(got.Reasons) == 0 || got.Error != "not removed: it is now keep" || !exists(dirty) {
		t.Fatalf("dirty removal = %+v", got)
	}
	if rep := h.Report(context.Background(), false); rep.Removals[done].State != RemovalRemoved {
		t.Fatalf("report removals = %+v", rep.Removals)
	}

	h.sizeWG.Wait()
	h.bgWG.Wait()
	h.now = func() time.Time { return time.Now().Add(48*time.Hour + removalTTL + time.Minute) }
	if left := h.Removals(); len(left) != 0 {
		t.Fatalf("finished removals kept past removalTTL: %+v", left)
	}
}
