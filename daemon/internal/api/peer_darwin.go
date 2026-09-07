//go:build darwin

package api

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// DarwinPeerChecker resolves peer credentials on macOS unix sockets.
type DarwinPeerChecker struct{}

func (DarwinPeerChecker) PeerCred(c net.Conn) (PeerCred, error) {
	sc, ok := c.(*net.UnixConn)
	if !ok {
		return PeerCred{}, errors.New("peer: not a unix socket connection")
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
		// LOCAL_PEEREPID: pid of the connected peer (0 if the peer closed).
		v, e := unix.GetsockoptInt(int(fd), 0 /* SOL_LOCAL */, unix.LOCAL_PEEREPID)
		if e != nil {
			cerr = fmt.Errorf("peer: LOCAL_PEEREPID: %w", e)
			return
		}
		cred.PID = int32(v)

		// LOCAL_PEERCRED: struct xucred with the peer's effective uid.
		x, e := unix.GetsockoptXucred(int(fd), 0 /* SOL_LOCAL */, unix.LOCAL_PEERCRED)
		if e != nil {
			cerr = fmt.Errorf("peer: LOCAL_PEERCRED: %w", e)
			return
		}
		cred.UID = int(x.Uid)
	}); err != nil {
		return PeerCred{}, fmt.Errorf("peer: control: %w", err)
	}
	if cerr != nil {
		return PeerCred{}, cerr
	}
	return cred, nil
}

// NewPeerChecker returns the platform's kernel-attested peer checker.
func NewPeerChecker() PeerChecker { return DarwinPeerChecker{} }
