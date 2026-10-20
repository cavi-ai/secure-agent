//go:build linux

package collect

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
)

// procRoot is /proc; a test seam.
var procRoot = "/proc"

// openRolloutFiles reads each pid's /proc/<pid>/fd links. A pid that exited
// or belongs to another uid is skipped.
func openRolloutFiles(ctx context.Context, pids []int32) (map[int32][]string, error) {
	out := map[int32][]string{}
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		dir := filepath.Join(procRoot, strconv.Itoa(int(pid)), "fd")
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			link, err := os.Readlink(filepath.Join(dir, fd.Name()))
			if err == nil && IsCodexRolloutPath(link) {
				out[pid] = append(out[pid], link)
			}
		}
	}
	return out, nil
}
