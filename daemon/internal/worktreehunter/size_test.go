package worktreehunter

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestDirSizeCountsAllocatedBytesAndSkipsNestedWorktrees(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a.bin"), string(make([]byte, 10000)))
	write(t, filepath.Join(root, "sub", "b.bin"), string(make([]byte, 5000)))
	write(t, filepath.Join(root, "nested", "big.bin"), string(make([]byte, 50000)))
	if err := os.Symlink("/", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	all, partial := dirSize(context.Background(), root, nil)
	if partial || all < 65000 {
		t.Fatalf("dirSize = %d partial=%v, want >= 65000 allocated", all, partial)
	}
	skipped, _ := dirSize(context.Background(), root, map[string]bool{filepath.Join(root, "nested"): true})
	if skipped >= all || skipped < 15000 {
		t.Fatalf("with nested skipped = %d (all %d)", skipped, all)
	}

	old := maxSizeEntries
	maxSizeEntries = 2
	t.Cleanup(func() { maxSizeEntries = old })
	if _, partial := dirSize(context.Background(), root, nil); !partial {
		t.Fatal("a walk past maxSizeEntries must report partial")
	}
}

func TestVolumeUsageOneRowPerVolume(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	v := volumeUsage([]string{a, b, "/nonexistent/x"})
	if len(v) != 1 || v[0].TotalBytes == 0 || v[0].FreeBytes == 0 || v[0].FreeBytes > v[0].TotalBytes || v[0].Mount == "" {
		t.Fatalf("volumes = %+v", v)
	}
}

func TestReportSizesInBackgroundWithoutTouchingTheCache(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	done := f.worktree(t, "done")
	write(t, filepath.Join(done, "node_modules", "pkg", "big.js"), string(make([]byte, 40000)))
	busy := f.worktree(t, "busy")
	write(t, filepath.Join(busy, "wip.txt"), "wip\n")
	age(t, done, 72*time.Hour)

	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	h := New(st, home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }

	first := h.Report(context.Background(), true)
	if !first.Sizing || findRow(t, first, done).SizeBytes != 0 {
		t.Fatalf("first report must be sizing with no size yet: sizing=%v", first.Sizing)
	}
	h.sizeWG.Wait()
	rep := h.Report(context.Background(), false)
	if rep.Sizing {
		t.Fatal("still sizing after the sizer finished")
	}
	d, b := findRow(t, rep, done), findRow(t, rep, busy)
	if d.State != StateRemove || d.SizeBytes < 40000 || b.SizeBytes <= 0 {
		t.Fatalf("done %s %d, busy %d", d.State, d.SizeBytes, b.SizeBytes)
	}
	if rep.Repos[0].SizeBytes != d.SizeBytes+b.SizeBytes || rep.Summary.SizeBytes != rep.Repos[0].SizeBytes || rep.Summary.RemovableBytes != d.SizeBytes {
		t.Fatalf("totals: repo %d summary %d removable %d (done %d busy %d)",
			rep.Repos[0].SizeBytes, rep.Summary.SizeBytes, rep.Summary.RemovableBytes, d.SizeBytes, b.SizeBytes)
	}
	if len(rep.Volumes) == 0 {
		t.Fatal("no volume usage")
	}
	if cached := h.report(context.Background(), false); findRow(t, cached, done).SizeBytes != 0 {
		t.Fatal("decorating a report wrote sizes into the cached scan")
	}

	if _, err := h.Remove(context.Background(), done); err != nil {
		t.Fatal(err)
	}
	if len(st.cleanup) != 1 || st.cleanup[0].Action != "worktree-remove" || st.cleanup[0].Bytes < 40000 || st.cleanup[0].Repo != f.main {
		t.Fatalf("ledger = %+v", st.cleanup)
	}
}

func TestMergeSharedVolumes(t *testing.T) {
	got := mergeShared([]VolumeUsage{
		{Mount: "/Volumes/MIRZA", TotalBytes: 8000, FreeBytes: 500},
		{Mount: "/Volumes/USB", TotalBytes: 1000, FreeBytes: 900},
		{Mount: "/System/Volumes/Data", TotalBytes: 8000, FreeBytes: 500},
	})
	if len(got) != 2 || got[0].Mount != "/Volumes/MIRZA + /System/Volumes/Data" || got[1].Mount != "/Volumes/USB" {
		t.Fatalf("merged = %+v", got)
	}
}
