// Package toolpath finds developer tools the daemon runs on the user's
// behalf. A launchd agent's PATH is only the system directories; tools live
// in Homebrew, ~/.local/bin, ~/.cargo/bin and the like.
package toolpath

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Dirs are the usual install directories under home, after the system ones.
func Dirs(home string) []string {
	return []string{
		"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
		filepath.Join(home, ".local", "bin"), filepath.Join(home, ".cargo", "bin"),
		filepath.Join(home, "go", "bin"), filepath.Join(home, ".volta", "bin"),
		filepath.Join(home, ".bun", "bin"), filepath.Join(home, "Library", "pnpm"),
		filepath.Join(home, ".npm-global", "bin"),
	}
}

// Look resolves name: the daemon's PATH first, then dirs. "" when absent.
func Look(name string, dirs []string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range dirs {
		if p, err := exec.LookPath(filepath.Join(d, name)); err == nil {
			return p
		}
	}
	return ""
}

// Env is the environment for running bin: the tool's own directory first
// (npm needs its node), then dirs, the daemon's PATH and the system dirs.
func Env(bin string, dirs []string) []string {
	path := append(append([]string{filepath.Dir(bin)}, dirs...), os.Getenv("PATH"), "/usr/bin", "/bin")
	return append(os.Environ(), "PATH="+strings.Join(path, ":"))
}

// Command builds a run of bin with Env, in its own process group: when ctx
// ends, the whole group is killed (the tool and whatever it started) and
// Wait stops waiting on pipes a straggler still holds.
func Command(ctx context.Context, bin string, dirs []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = Env(bin, dirs)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	return cmd
}
