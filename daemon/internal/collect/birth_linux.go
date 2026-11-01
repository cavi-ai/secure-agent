package collect

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// fileBirth is when the file at path was created, or its modification time
// when the filesystem does not record one.
func fileBirth(path string, fi os.FileInfo) time.Time {
	var st unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &st) == nil && st.Mask&unix.STATX_BTIME != 0 {
		return time.Unix(st.Btime.Sec, int64(st.Btime.Nsec))
	}
	return fi.ModTime()
}
