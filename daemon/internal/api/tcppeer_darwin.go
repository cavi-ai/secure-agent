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
// connection to this process, from `lsof`. Anything but exactly one other
// process on that address is an error.
func TCPClientPID(remoteAddr string) (int32, error) {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return 0, fmt.Errorf("peer %s is not loopback", remoteAddr)
	}
	spec := "-iTCP@" + host + ":" + port
	if ip.To4() == nil {
		spec = "-iTCP@[" + host + "]:" + port
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// lsof exits 1 when it finds nothing; the pid count decides.
	out, _ := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", spec, "-sTCP:ESTABLISHED", "-Fp").Output()
	pids := ParseLsofPIDs(out, os.Getpid())
	if len(pids) != 1 {
		return 0, fmt.Errorf("peer %s: %d candidate processes", remoteAddr, len(pids))
	}
	return pids[0], nil
}
