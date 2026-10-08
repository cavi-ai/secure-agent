//go:build darwin || linux

package collect

import (
	"fmt"
	"os"
	"syscall"
)

func sourceIdentity(fi os.FileInfo) string {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", s.Dev, s.Ino)
	}
	return ""
}
