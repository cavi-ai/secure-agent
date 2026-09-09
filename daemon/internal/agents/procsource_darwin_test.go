//go:build darwin

package agents

import (
	"bytes"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func getProcPathSysctl(pid int32) string {
	mib := []int32{1 /* CTL_KERN */, 49 /* KERN_PROCARGS2 */, pid}
	n := uintptr(0)
	// Get buffer size needed
	_, _, err := unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		0,
		uintptr(unsafe.Pointer(&n)),
		0,
		0,
	)
	if err != 0 || n == 0 {
		return ""
	}
	buf := make([]byte, n)
	_, _, err = unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n)),
		0,
		0,
	)
	if err != 0 || n <= 4 {
		return ""
	}
	// KERN_PROCARGS2 returns argc (int32, 4 bytes) followed by null-terminated executable path
	pathBuf := buf[4:]
	idx := bytes.IndexByte(pathBuf, 0)
	if idx > 0 {
		return string(pathBuf[:idx])
	}
	return ""
}

func TestSysctlProcArgs2(t *testing.T) {
	pid := int32(os.Getpid())
	path := getProcPathSysctl(pid)
	t.Logf("getProcPathSysctl(%d) = %q", pid, path)
	if path == "" {
		t.Fatalf("Failed to get path for self PID %d", pid)
	}
}

func TestSelfStartTimeAndRSS(t *testing.T) {
	src := NewDarwinProcSource()
	info, ok := src.Info(int32(os.Getpid()))
	if !ok {
		t.Fatal("Info(self) failed")
	}
	if info.StartTime.IsZero() {
		t.Fatal("StartTime is zero")
	}
	if info.StartTime.After(time.Now().Add(time.Minute)) {
		t.Fatalf("StartTime in the future: %v", info.StartTime)
	}
	if info.RSSBytes == 0 {
		t.Log("RSSBytes is 0 (proc_info may be restricted); start time still required")
	}
}
