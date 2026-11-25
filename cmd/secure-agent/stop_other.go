//go:build !darwin

package main

import (
	"errors"
	"net"
)

// socketPeer has no pid-version identity off macOS, so stop signals nothing there.
func socketPeer(*net.UnixConn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("secure-agent stop is supported on macOS only")
}

func ownedByApp(int) bool { return false }
