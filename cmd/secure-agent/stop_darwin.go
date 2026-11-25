//go:build darwin

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// socketPeer reads the audit token (pid and pid version) of the process
// serving the connected control socket.
func socketPeer(c *net.UnixConn) (peerIdentity, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return peerIdentity{}, err
	}
	var (
		id   peerIdentity
		cerr error
	)
	if err := raw.Control(func(fd uintptr) {
		var token [8]uint32
		size := uint32(unsafe.Sizeof(token))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, 0 /* SOL_LOCAL */, unix.LOCAL_PEERTOKEN, uintptr(unsafe.Pointer(&token[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 || size != 32 || token[5] == 0 || token[7] == 0 {
			cerr = fmt.Errorf("control socket peer identity unavailable: %v", errno)
			return
		}
		id = peerIdentity{PID: int(token[5]), Version: token[7]}
	}); err != nil {
		return peerIdentity{}, err
	}
	return id, cerr
}

// ownedByApp reports whether pid's parent is the Secure Agent app, by the
// same parent test the daemon uses to find its owning app.
func ownedByApp(pid int) bool {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp.Eproc.Ppid <= 1 {
		return false
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(int(kp.Eproc.Ppid)), "-o", "comm=").Output()
	return err == nil && strings.HasSuffix(strings.TrimSpace(string(out)), ".app/Contents/MacOS/SecureAgent")
}
