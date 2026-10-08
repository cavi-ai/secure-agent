//go:build darwin

package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

// TCPClientPID returns the pid holding the client end of a loopback TCP
// connection to this process, from `netstat -anv`, which reads the kernel's
// connection table instead of every process's open files. Anything but
// exactly one other process on that address is an error.
func TCPClientPID(remoteAddr string) (int32, error) {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return 0, fmt.Errorf("peer %s is not loopback", remoteAddr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/netstat", "-anv", "-p", "tcp").Output()
	if err != nil {
		return 0, fmt.Errorf("peer %s: netstat: %w", remoteAddr, err)
	}
	pids := ParseNetstatClientPIDs(out, host+"."+port, os.Getpid())
	if len(pids) != 1 {
		return 0, fmt.Errorf("peer %s: %d candidate processes", remoteAddr, len(pids))
	}
	return pids[0], nil
}
