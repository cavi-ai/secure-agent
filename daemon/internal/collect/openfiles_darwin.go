//go:build darwin

package collect

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

func openRolloutFiles(pids []int32) (map[int32][]string, error) {
	return lsofRolloutFiles(execOutput, lsofBinary(), pids)
}

// lsofBinary resolves lsof as the net sampler does: PATH, then /usr/sbin.
func lsofBinary() string {
	if path, err := exec.LookPath("lsof"); err == nil {
		return path
	}
	if _, err := os.Stat("/usr/sbin/lsof"); err == nil {
		return "/usr/sbin/lsof"
	}
	return "lsof"
}

// execOutput runs a command under ctx. Exit status 1 is lsof's "a named pid
// is gone", not a failure.
func execOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		err = nil
	}
	return out, err
}
