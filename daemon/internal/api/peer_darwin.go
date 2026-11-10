//go:build darwin

package api

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

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
		var token [8]uint32
		size := uint32(unsafe.Sizeof(token))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, 0 /* SOL_LOCAL */, unix.LOCAL_PEERTOKEN, uintptr(unsafe.Pointer(&token[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 || size != 32 || token[5] == 0 || token[7] == 0 {
			cerr = fmt.Errorf("peer: audit token unavailable: %v", errno)
			return
		}
		cred = PeerCred{PID: int32(token[5]), UID: int(token[1]), PIDVersion: token[7]}
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
