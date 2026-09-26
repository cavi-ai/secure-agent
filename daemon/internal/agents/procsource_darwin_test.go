//go:build darwin

package agents

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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

func TestProcEnvVarReadsChild(t *testing.T) {
	// KERN_PROCARGS2 reports the environment AT EXEC, and macOS redacts it
	// for platform binaries (/bin/sleep shows nothing even to ps eww), so the
	// child is this test binary re-executed as a blocking helper.
	cmd := exec.Command(os.Args[0], "-test.run=TestEnvHelperProcess")
	cmd.Env = append(os.Environ(),
		"SECURE_AGENT_TEST_ENVVAR=probe-value-123",
		"GO_WANT_HELPER_PROCESS=1",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := ProcEnvVar(int32(cmd.Process.Pid), "SECURE_AGENT_TEST_ENVVAR"); got == "probe-value-123" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ProcEnvVar(child) never returned the exec-time env var")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := ProcEnvVar(int32(cmd.Process.Pid), "SECURE_AGENT_TEST_MISSING"); got != "" {
		t.Fatalf("missing var = %q, want empty", got)
	}
}

// TestEnvHelperProcess blocks forever when re-executed by
// TestProcEnvVarReadsChild; run directly it is a no-op pass.
func TestEnvHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	select {}
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
	if info.CWD == "" {
		t.Fatal("CWD is empty")
	}
	if !filepath.IsAbs(info.CWD) {
		t.Fatalf("CWD is not absolute: %q", info.CWD)
	}
}

func TestDarwinArgv0ReadsOwnArgv0(t *testing.T) {
	got := (&DarwinProcSource{}).Argv0(int32(os.Getpid()))
	if got != os.Args[0] {
		t.Fatalf("Argv0(self) = %q, want %q", got, os.Args[0])
	}
	if (&DarwinProcSource{}).Argv0(-1) != "" {
		t.Fatal("Argv0 of an invalid pid must be empty")
	}
}
