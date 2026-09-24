package clutter

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// gitTimeout bounds one git call of the ignore check.
const gitTimeout = 20 * time.Second

// disposable reports, for each candidate directory inside the repository
// or worktree at place, whether it may be cleared: git ignores it and no
// tracked file lives under it. A name like build/ or dist/ can be source in
// some repositories; only what git itself ignores is offered. A git failure
// answers false for every candidate (listed, never cleared).
func disposable(ctx context.Context, place string, candidates []string) map[string]bool {
	out := map[string]bool{}
	if len(candidates) == 0 {
		return out
	}
	rel := make([]string, 0, len(candidates))
	for _, c := range candidates {
		r, err := filepath.Rel(place, c)
		if err != nil || strings.HasPrefix(r, "..") {
			continue
		}
		rel = append(rel, r)
	}
	ignoredOut, err := runGit(ctx, place, strings.Join(rel, "\x00")+"\x00", "check-ignore", "--stdin", "-z")
	if err != nil {
		return out
	}
	ignored := map[string]bool{}
	for _, r := range strings.Split(ignoredOut, "\x00") {
		if r != "" {
			ignored[strings.TrimSuffix(r, "/")] = true
		}
	}
	tracked, err := runGit(ctx, place, "", append([]string{"ls-files", "-z", "--"}, rel...)...)
	if err != nil {
		return out
	}
	hasTracked := map[string]bool{}
	for _, f := range strings.Split(tracked, "\x00") {
		for _, r := range rel {
			if f == r || strings.HasPrefix(f, r+"/") {
				hasTracked[r] = true
			}
		}
	}
	for _, r := range rel {
		out[filepath.Join(place, r)] = ignored[r] && !hasTracked[r]
	}
	return out
}

// runGit runs one read-only git command in dir; exit status 1 from
// check-ignore (nothing ignored) is not an error.
func runGit(ctx context.Context, dir, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir, "-c", "core.fsmonitor=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 && args[0] == "check-ignore" {
		return out.String(), nil
	}
	return out.String(), err
}
