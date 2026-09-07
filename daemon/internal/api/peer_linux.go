//go:build linux

package api

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// LinuxPeerChecker resolves peer credentials on Linux unix sockets via
// SO_PEERCRED — the kernel-attested pid/uid of the socket's peer.
type LinuxPeerChecker struct{}

func (LinuxPeerChecker) PeerCred(c net.Conn) (PeerCred, error) {
	sc, ok := c.(*net.UnixConn)
	if !ok {
		return PeerCred{}, errNotUnixConn
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return PeerCred{}, fmt.Errorf("peer: syscall conn: %w", err)
	}
	var (
		cred PeerCred
		cerr error
	)
	if err := raw.Control(func(fd uintptr) {
		u, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			cerr = fmt.Errorf("peer: SO_PEERCRED: %w", e)
			return
		}
		cred.PID = u.Pid
		cred.UID = int(u.Uid)
	}); err != nil {
		return PeerCred{}, fmt.Errorf("peer: control: %w", err)
	}
	if cerr != nil {
		return PeerCred{}, cerr
	}
	return cred, nil
}

// NewPeerChecker returns the platform's kernel-attested peer checker.
func NewPeerChecker() PeerChecker { return LinuxPeerChecker{} }
