//go:build !darwin && !linux

package collect

import (
	"os"
	"time"
)

// fileBirth is the file's modification time: no creation time here.
func fileBirth(_ string, fi os.FileInfo) time.Time { return fi.ModTime() }
