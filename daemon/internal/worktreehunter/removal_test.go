package worktreehunter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Remove all starts one removal per row at once: they queue on the scan
// lock and every one lands.
func TestStartRemoveManyInOneRepository(t *testing.T) {
	h, f := removalFixture(t)
	var paths []string
	for _, n := range []string{"a", "b", "c", "d"} {
		paths = append(paths, f.worktree(t, n))
	}
	for _, p := range paths {
		if _, err := h.StartRemove(p); err != nil {
			t.Fatalf("StartRemove(%s): %v", p, err)
		}
	}
	h.remWG.Wait()
	all := h.Removals()
	for _, p := range paths {
		if all[p].State != RemovalRemoved || exists(p) {
			t.Fatalf("%s: %+v, on disk %v", p, all[p], exists(p))
		}
	}
	if list := run(t, f.main, "worktree", "list", "--porcelain"); strings.Count(list, "worktree ") != 1 {
		t.Fatalf("git still lists linked worktrees:\n%s", list)
	}
}

// slowGit puts a git first on PATH whose first call after arm hangs until
// it is killed, leaving started behind; every other call runs the real git.
func slowGit(t *testing.T) (arm func(), started string) {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	armed, started := filepath.Join(dir, "armed"), filepath.Join(dir, "started")
	bin := filepath.Join(dir, "bin")
	write(t, filepath.Join(bin, "git"), fmt.Sprintf("#!/bin/sh\nif mv %q %q 2>/dev/null; then exec sleep 30; fi\nexec %q \"$@\"\n", armed, started, real))
	if err := os.Chmod(filepath.Join(bin, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() { write(t, armed, "") }, started
}

func waitForFile(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !exists(p) {
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", p)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A row action does not wait behind the background rescan the previous
// removal started: it cancels the rescan, and the rescan's partial report
// is neither cached nor saved.
func TestRowActionCancelsTheBackgroundRescan(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gone   bool // the target's directory is deleted before the first scan
		action func(h *Hunter, f fixture, target string) error
	}{
		{"remove", false, func(h *Hunter, _ fixture, target string) error {
			_, err := h.Remove(context.Background(), target)
			return err
		}},
		{"prune", true, func(h *Hunter, f fixture, _ string) error {
			_, err := h.Prune(context.Background(), f.main)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f := removalFixture(t)
			first, target := f.worktree(t, "first"), f.worktree(t, "target")
			if tc.gone {
				if err := os.RemoveAll(target); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			h.Report(ctx, false)
			_, savedAt, _ := h.st.ScanCache(cacheReportKey)
			if _, err := h.Remove(ctx, first); err != nil {
				t.Fatal(err)
			}
			arm, started := slowGit(t)
			arm()
			if !h.Report(ctx, false).Refreshing {
				t.Fatal("the report after a removal does not refresh")
			}
			waitForFile(t, started)

			begin := time.Now()
			if err := tc.action(h, f, target); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(begin); d > 10*time.Second {
				t.Fatalf("%s waited %s behind the background rescan", tc.name, d.Round(time.Second))
			}
			h.bgWG.Wait()
			if _, at, _ := h.st.ScanCache(cacheReportKey); !at.Equal(savedAt) {
				t.Fatal("the canceled rescan's report was saved")
			}
			if r, _, ok := h.cachedCopy(); ok && strings.Contains(strings.Join(r.Errors, "\n"), "stopped early") {
				t.Fatalf("the canceled rescan's report was cached: %v", r.Errors)
			}
		})
	}
}

// While a row action waits for the scan lock, a report on an old scan does
// not start a background rescan that would take the lock first; the next
// report after the action does.
func TestNoBackgroundRescanWhileAnActionWaits(t *testing.T) {
	h, f := removalFixture(t)
	f.worktree(t, "a")
	ctx := context.Background()
	h.Report(ctx, false)
	_, savedAt, _ := h.st.ScanCache(cacheReportKey)

	h.mu.Lock()
	h.actions++
	h.mu.Unlock()
	h.markStale()
	if !h.Report(ctx, false).Refreshing {
		t.Fatal("an old scan does not say refreshing")
	}
	h.bgWG.Wait()
	if _, at, _ := h.st.ScanCache(cacheReportKey); !at.Equal(savedAt) {
		t.Fatal("a background rescan ran while an action waited")
	}

	h.mu.Lock()
	h.actions--
	h.mu.Unlock()
	h.Report(ctx, false)
	h.bgWG.Wait()
	if _, at, _ := h.st.ScanCache(cacheReportKey); at.Equal(savedAt) {
		t.Fatal("no background rescan after the action")
	}
}

type phaseRecorder struct {
	seen  []string
	bytes int64
	files int
}

func (r *phaseRecorder) phase(p string) {
	if p == PhaseDeleting && r.files > 0 {
		p += "(measured)"
	}
	r.seen = append(r.seen, p)
}

func (r *phaseRecorder) measured(bytes int64, files int) { r.bytes, r.files = bytes, files }

// A removal passes its phases in order and reports the measured size of
// the tree before it starts deleting it.
func TestRemovePassesPhasesInOrderAndMeasuresBeforeDeleting(t *testing.T) {
	h, f := removalFixture(t)
	wt := f.worktree(t, "done")
	for i := 0; i < 20; i++ {
		write(t, filepath.Join(wt, "node_modules", fmt.Sprintf("f%d.js", i)), "x\n")
	}
	rec := &phaseRecorder{}
	if _, err := h.remove(context.Background(), wt, rec); err != nil || exists(wt) {
		t.Fatalf("remove = %v, still on disk %v", err, exists(wt))
	}
	if got := strings.Join(rec.seen, ","); got != "checking,measuring,deleting(measured)" {
		t.Fatalf("phases = %s", got)
	}
	if rec.bytes <= 0 || rec.files < 20 {
		t.Fatalf("measured %d bytes, %d files; want > 0 and >= 20", rec.bytes, rec.files)
	}
}

// While a removal runs, Removals names its phase, when that phase began
// and, once measured, the size and file count being deleted; the phase
// clears when it ends and the size stays.
func TestRemovalReportsPhaseSizeAndFilesWhileRunning(t *testing.T) {
	h, f := removalFixture(t)
	wt := f.worktree(t, "done")
	job, err := h.beginRemoval(wt)
	if err != nil {
		t.Fatal(err)
	}
	job.phase(PhaseMeasuring)
	job.measured(4096, 7)
	job.phase(PhaseDeleting)
	got := h.Removals()[wt]
	if got.State != RemovalRunning || got.Phase != PhaseDeleting || got.Step != StepDeleting || got.StepAt == nil || got.Bytes != 4096 || got.Files != 7 {
		t.Fatalf("running removal = %+v", got)
	}
	job.finish(Worktree{Branch: "feat/done", SizeBytes: 4096}, nil)
	got = h.Removals()[wt]
	if got.State != RemovalRemoved || got.Phase != "" || got.Step != "" || got.StepAt != nil || got.Bytes != 4096 || got.Files != 7 {
		t.Fatalf("finished removal = %+v", got)
	}
}
