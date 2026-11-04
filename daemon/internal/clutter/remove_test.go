package clutter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestRemoveRepositoryCache(t *testing.T) {
	m := newMachine(t)
	st := &memStore{}
	c := m.clutter(st)
	t.Cleanup(c.Wait)
	outside := filepath.Join(m.home, "keep.txt")
	mk(t, outside, 123)
	target := filepath.Join(m.repo, "node_modules")
	if err := os.Symlink(outside, filepath.Join(target, "outside")); err != nil {
		t.Fatal(err)
	}
	res, err := c.Remove(context.Background(), target)
	if err != nil || res.Bytes < 8000 || res.TrashAt != "" {
		t.Fatalf("remove: %+v %v", res, err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache remains: %v", err)
	}
	for _, p := range []string{outside, filepath.Join(m.repo, "src", "main.go")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("preserved file %s: %v", p, err)
		}
	}
	if len(st.ledger) != 1 || st.ledger[0].Action != "clean:build-cache" || st.ledger[0].Bytes != res.Bytes {
		t.Fatalf("ledger: %+v", st.ledger)
	}
}

func TestRemoveRejectsSourceScratchAndLiveCaches(t *testing.T) {
	m := newMachine(t)
	st := &memStore{}
	c := m.clutter(st)
	t.Cleanup(c.Wait)
	for _, path := range []string{m.repo, m.wt, filepath.Join(m.repo, "src"), filepath.Join(m.repo, "build"), filepath.Join(m.repo, ".tmp")} {
		if _, err := c.Remove(context.Background(), path); !errors.Is(err, ErrNotInInventory) {
			t.Fatalf("remove %s: %v", path, err)
		}
	}
	st.activity = []model.WorkspaceActivity{{Workspace: m.repo, Live: true}}
	if _, err := c.Remove(context.Background(), filepath.Join(m.repo, "node_modules")); !errors.Is(err, ErrNotInInventory) {
		t.Fatalf("live cache: %v", err)
	}
	if len(st.ledger) != 0 {
		t.Fatalf("refused deletion recorded: %+v", st.ledger)
	}
}

func TestUnityCacheDiscoveryAndEditorProtection(t *testing.T) {
	m := newMachine(t)
	st := &memStore{}
	c := m.clutter(st)
	t.Cleanup(c.Wait)
	project := filepath.Join(m.repo, "game", "unity")
	target := filepath.Join(project, "Library")
	mk(t, filepath.Join(project, "Assets", "scene.unity"), 10)
	mk(t, filepath.Join(project, "ProjectSettings", "ProjectVersion.txt"), 10)
	mk(t, filepath.Join(target, "cache"), 100)
	mk(t, filepath.Join(m.repo, "Library", "source"), 100)
	f, err := os.OpenFile(filepath.Join(m.repo, ".gitignore"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("game/unity/Library/\n")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	item := byPath(t, c.Report(context.Background(), true), target)
	if !item.CanRemove {
		t.Fatalf("Unity cache not removable: %+v", item)
	}
	for _, it := range c.Report(context.Background(), true).Items {
		if it.Path == filepath.Join(m.repo, "Library") {
			t.Fatal("non-Unity Library offered as cache")
		}
	}
	if err := os.WriteFile(filepath.Join(target, "EditorInstance.json"), []byte(fmt.Sprintf(`{"process_id":%d}`, os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Remove(context.Background(), target); !errors.Is(err, ErrNotInInventory) {
		t.Fatalf("live Unity editor cache: %v", err)
	}
}
