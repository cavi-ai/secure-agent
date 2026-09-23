package worktreehunter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// gitTimeout bounds one git invocation. A wedged repository (network mount,
// giant untracked tree) costs one row, never the scan.
const gitTimeout = 10 * time.Second

// gitEnv makes every call read-only toward the repositories it inspects:
// GIT_OPTIONAL_LOCKS=0 stops `git status` from refreshing and rewriting the
// index of a tree an agent may be working in; no prompts, no pager, stable
// English output for parsing.
var gitEnv = []string{
	"GIT_OPTIONAL_LOCKS=0",
	"GIT_TERMINAL_PROMPT=0",
	"GIT_PAGER=cat",
	"LC_ALL=C",
}

// gitArgs prefixes every call: -C runs in dir; fsmonitor off so a scan never
// starts a watcher daemon in someone's repository.
func gitArgs(dir string, args ...string) []string {
	return append([]string{"-C", dir, "-c", "core.fsmonitor=false"}, args...)
}

func gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", gitArgs(dir, args...)...)
	cmd.Env = append(os.Environ(), gitEnv...)
	return cmd
}

// git runs one command and returns stdout. The error carries stderr's first
// line, which is what an operator needs ("detected dubious ownership", "not
// a git repository").
func git(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := gitCommand(ctx, dir, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg, _, _ := strings.Cut(strings.TrimSpace(errb.String()), "\n")
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), fmt.Errorf("git %s: %s", args[0], msg)
	}
	return out.String(), nil
}

// gitOK runs a command whose exit status is the answer (merge-base
// --is-ancestor). A timeout or a missing binary is an error, not "false".
func gitOK(ctx context.Context, dir string, args ...string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	err := gitCommand(ctx, dir, args...).Run()
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// patchIDs pipes `git <args>` (a diff or log -p) through `git patch-id
// --stable` and returns the patch ids. Streamed: a long log never sits in
// memory.
func patchIDs(ctx context.Context, dir string, timeout time.Duration, args ...string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	src := gitCommand(ctx, dir, args...)
	pid := gitCommand(ctx, dir, "patch-id", "--stable")
	r, w := io.Pipe()
	src.Stdout = w
	pid.Stdin = r
	var out bytes.Buffer
	pid.Stdout = &out
	if err := pid.Start(); err != nil {
		return nil, err
	}
	srcErr := src.Run()
	w.Close()
	pidErr := pid.Wait()
	if srcErr != nil {
		return nil, fmt.Errorf("git %s: %w", args[0], srcErr)
	}
	if pidErr != nil {
		return nil, fmt.Errorf("git patch-id: %w", pidErr)
	}
	var ids []string
	for _, line := range strings.Split(out.String(), "\n") {
		if id, _, ok := strings.Cut(line, " "); ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
