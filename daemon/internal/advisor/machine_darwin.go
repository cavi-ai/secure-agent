//go:build darwin

package advisor

import "golang.org/x/sys/unix"

func chipName() string {
	s, _ := unix.Sysctl("machdep.cpu.brand_string")
	return s
}

func totalRAM() uint64 {
	n, _ := unix.SysctlUint64("hw.memsize")
	return n
}
