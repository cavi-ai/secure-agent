//go:build linux

package advisor

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func chipName() string { return runtime.GOARCH }

func totalRAM() uint64 {
	var info unix.Sysinfo_t
	if unix.Sysinfo(&info) != nil {
		return 0
	}
	return uint64(info.Totalram) * uint64(info.Unit)
}
