package api

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerCred identifies the local process on the other end of a unix-socket
// connection. Fetched with LOCAL_PEEREPID / LOCAL_PEERCRED, so it cannot be
// forged by the client: the kernel attests the credentials of the socket's
// creator.
type PeerCred struct {
	PID int32
	UID int
}

// PeerChecker resolves the kernel-attested identity of a connection's remote
// end. The darwin implementation uses LOCAL_PEEREPID/LOCAL_PEERCRED; tests
// substitute a fake.
type PeerChecker interface {
	PeerCred(c net.Conn) (PeerCred, error)
}

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