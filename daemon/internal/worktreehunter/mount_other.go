//go:build !darwin

package worktreehunter

import "golang.org/x/sys/unix"

// mountPoint is unknown from statfs here; callers fall back to volumeRoot.
func mountPoint(*unix.Statfs_t) string { return "" }
