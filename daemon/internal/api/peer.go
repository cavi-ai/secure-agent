package api

import (
	"errors"
	"net"
)

// PeerCred identifies the local process on the other end of a unix-socket
// connection, attested by the kernel (LOCAL_PEEREPID/LOCAL_PEERCRED on macOS,
// SO_PEERCRED on Linux), so it cannot be forged by the client.
type PeerCred struct {
	PID int32
	UID int
}

// PeerChecker resolves the kernel-attested identity of a connection's remote
// end. Tests substitute a fake.
type PeerChecker interface {
	PeerCred(c net.Conn) (PeerCred, error)
}

// errNotUnixConn is shared by the platform implementations.
var errNotUnixConn = errors.New("peer: not a unix socket connection")
