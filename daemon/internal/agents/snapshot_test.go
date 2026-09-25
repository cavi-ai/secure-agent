package agents

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// snapProcs is a process table that can also read argv[0].
type snapProcs struct {
	procs map[int32]ProcInfo
	argv0 map[int32]string
}

func (s snapProcs) List() []ProcInfo {
	out := make([]ProcInfo, 0, len(s.procs))
	for _, p := range s.procs {
		out = append(out, p)
	}
	return out
}

func (s snapProcs) Info(pid int32) (ProcInfo, bool) {
	p, ok := s.procs[pid]
	return p, ok
}

func (s snapProcs) Argv0(pid int32) string { return s.argv0[pid] }

const claudeCodeExe = "/Users/dev/Library/Application Support/Claude/claude-code/2.1.281/claude.app/Contents/MacOS/claude"

func TestSnapshotNamesLauncherFromAncestry(t *testing.T) {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	ps := snapProcs{
		procs: map[int32]ProcInfo{
			100: {PID: 100, PPID: 1, Exe: "/Applications/Claude.app/Contents/MacOS/Claude"},
			200: {PID: 200, PPID: 100, Exe: claudeCodeExe},
			300: {PID: 300, PPID: 200, Exe: "/bin/zsh"},
		},
		argv0: map[int32]string{200: "claude", 300: "-zsh GH_TOKEN=[REDACTED] PATH=/usr/bin"},
	}
	tg := New(cfg, ps)
	tg.Refresh()
	if _, ok := tg.Tag(300); !ok {
		t.Fatal("zsh under claude must tag")
	}
	got, ok := tg.Snapshot(300)
	if !ok {
		t.Fatal("snapshot of a tagged pid must succeed")
	}
	if got.Name != "zsh" || got.Exe != "/bin/zsh" || got.PPID != 200 || got.Args0 != "-zsh" ||
		got.Launcher != "Claude.app › claude-code 2.1.281" {
		t.Fatalf("snapshot = %+v", got)
	}
	root, _ := tg.Snapshot(200)
	if root.Name != "claude" || root.Launcher != "Claude.app › claude-code 2.1.281" {
		t.Fatalf("root snapshot = %+v", root)
	}
	if _, ok := tg.Snapshot(999); ok {
		t.Fatal("unknown pid must not snapshot")
	}
}

func TestSanitizeArgv0CutsEnvironmentAndScrubs(t *testing.T) {
	for in, want := range map[string]string{
		"claude":                              "claude",
		"Cursor Helper (Plugin): host A=1":    "Cursor Helper (Plugin): host",
		"tool AKIA" + "ABCDEFGH" + "IJKLMNOP": "tool [REDACTED]",
	} {
		if got := SanitizeArgv0(in); got != want {
			t.Fatalf("SanitizeArgv0(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHarnessLabel(t *testing.T) {
	for exe, want := range map[string]string{
		claudeCodeExe: "claude-code 2.1.281",
		"/Users/dev/.local/share/claude/versions/2.1.281": "claude 2.1.281",
		"/Applications/Cursor.app/Contents/MacOS/Cursor":  "Cursor.app",
		"/opt/homebrew/bin/opencode":                      "opencode",
	} {
		if got := HarnessLabel(exe); got != want {
			t.Fatalf("HarnessLabel(%q) = %q, want %q", exe, got, want)
		}
	}
}
