package worktreehunter

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

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
