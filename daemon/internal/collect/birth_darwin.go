package collect

import (
	"os"
	"syscall"
	"time"
)

// fileBirth is when the file at path was created, or its modification time
// when the filesystem does not record one.
func fileBirth(_ string, fi os.FileInfo) time.Time {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok && s.Birthtimespec.Sec > 0 {
		return time.Unix(s.Birthtimespec.Sec, s.Birthtimespec.Nsec)
	}
	return fi.ModTime()
}
