package clutter

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitCheckFailureReportsTheCause(t *testing.T) {
	m := newMachine(t)
	if err := os.Rename(filepath.Join(m.repo, ".git"), filepath.Join(m.repo, ".git-unavailable")); err != nil {
		t.Fatal(err)
	}
	c := m.clutter(&memStore{})
	t.Cleanup(c.Wait)
	it := byPath(t, c.Report(context.Background(), true), filepath.Join(m.repo, ".tmp"))
	if it.Action != ActionNone || !strings.Contains(it.Note, "not a git repository") || strings.Contains(it.Note, "not ignored") {
		t.Fatalf("failed verification must explain the Git error without claiming the directory is tracked: %+v", it)
	}
}

func TestCanceledRefreshPreservesTheLastInventory(t *testing.T) {
	m := newMachine(t)
	st := &memStore{}
	c := m.clutter(st)
	t.Cleanup(c.Wait)
	c.Report(context.Background(), true)
	c.Wait()
	before, at, ok := st.ScanCache(cacheInventoryKey)
	if !ok {
		t.Fatal("initial inventory was not saved")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Report(ctx, true)
	after, savedAt, _ := st.ScanCache(cacheInventoryKey)
	if !bytes.Equal(before, after) || !savedAt.Equal(at) {
		t.Error("canceled refresh overwrote the saved inventory")
	}
	it := byPath(t, c.Report(context.Background(), false), filepath.Join(m.repo, ".tmp"))
	if it.Action != ActionTrash {
		t.Fatalf("canceled refresh replaced the cached Git facts: %+v", it)
	}
}

func TestCanceledTrashLeavesTheDirectoryInPlace(t *testing.T) {
	m := newMachine(t)
	st := &memStore{}
	c := m.clutter(st)
	t.Cleanup(c.Wait)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(m.ws, ".quarantine")
	if _, err := c.Trash(ctx, path); !errors.Is(err, context.Canceled) {
		t.Errorf("Trash with a canceled request: %v, want context.Canceled", err)
	}
	if _, err := os.Stat(filepath.Join(path, "stale.zip")); err != nil {
		t.Errorf("canceled request moved the directory: %v", err)
	}
	if len(st.ledger) != 0 {
		t.Error("canceled request recorded a cleanup")
	}
}
