package worktreehunter

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseStatus(t *testing.T) {
	out := strings.Join([]string{
		"# branch.oid 0123456789abcdef",
		"# branch.head feat/x",
		"# branch.upstream origin/feat/x",
		"# branch.ab +2 -3",
		"1 .M N... 100644 100644 100644 aaa bbb dir/with space.txt",
		"2 R. N... 100644 100644 100644 aaa bbb R100 new name.txt",
		"old name.txt",
		"u UU N... 100644 100644 100644 100644 aaa bbb ccc conflict.go",
		"? scratch/",
		"",
	}, "\x00")
	got := parseStatus(out)
	want := statusFacts{
		Upstream: "origin/feat/x", Ahead: 2, Behind: 3,
		Changed: 2, Untracked: 1, Conflicts: 1,
		Paths: []string{"dir/with space.txt", "new name.txt", "conflict.go", "scratch/"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseStatus =\n%+v\nwant\n%+v", got, want)
	}

	gone := parseStatus("# branch.oid abc\x00# branch.head x\x00# branch.upstream origin/x\x00")
	if !gone.UpstreamGone {
		t.Fatal("upstream without branch.ab must read as gone")
	}
	none := parseStatus("# branch.oid abc\x00# branch.head x\x00")
	if none.UpstreamGone {
		t.Fatal("no upstream must not read as gone")
	}
}

func TestParseWorktreeList(t *testing.T) {
	out := "worktree /r\nHEAD aaa\nbranch refs/heads/main\n\n" +
		"worktree /r/.worktrees/a\nHEAD bbb\nbranch refs/heads/feat/a\nlocked agent busy\n\n" +
		"worktree /r/.worktrees/b\nHEAD ccc\ndetached\nprunable gitdir file points to non-existent location\n\n"
	got := parseWorktreeList(out)
	want := []listed{
		{Path: "/r", Head: "aaa", Branch: "main"},
		{Path: "/r/.worktrees/a", Head: "bbb", Branch: "feat/a", Locked: true, LockReason: "agent busy"},
		{Path: "/r/.worktrees/b", Head: "ccc", Detached: true, Prunable: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWorktreeList =\n%+v\nwant\n%+v", got, want)
	}
}

func TestClassifyIgnored(t *testing.T) {
	got := classifyIgnored([]string{
		".env", ".env.local", ".claude/", ".tmp/evidence.log", "certs/server.pem", "id.key",
		"node_modules/", "dist/", ".DS_Store", ".claude/.DS_Store", "pkg/.remember/", "",
	})
	wantPrecious := []string{".env", ".env.local", ".claude/", ".tmp/evidence.log", "certs/server.pem", "id.key", "pkg/.remember/"}
	if !reflect.DeepEqual(got.Precious, wantPrecious) || got.Other != 4 {
		t.Fatalf("classifyIgnored = %+v, want precious %v and 4 other", got, wantPrecious)
	}
}

func TestDescribeEntry(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, size int) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk(".tmp/a.log", 1024)
	mk(".tmp/sub/b.log", 1536)
	mk(".tmp/.DS_Store", 9999)
	mk(".claude/.DS_Store", 10)
	mk(".env", 42)

	for entry, want := range map[string]string{
		".tmp/": ".tmp/ (2 files, 2.5 KB)",
		".env":  ".env (42 B)",
	} {
		if got, ok := describeEntry(root, entry); !ok || got != want {
			t.Errorf("describeEntry(%q) = %q, %v; want %q", entry, got, ok, want)
		}
	}
	if got, ok := describeEntry(root, ".claude/"); ok {
		t.Errorf("a directory holding only junk must drop out, got %q", got)
	}
	if got := humanBytes(3 << 20); got != "3.0 MB" {
		t.Errorf("humanBytes(3 MiB) = %q", got)
	}
}
