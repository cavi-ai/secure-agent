package daemon

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootTime is when this machine last booted, from the kern.boottime sysctl.
func bootTime() (time.Time, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*int64(time.Microsecond)), nil
}
