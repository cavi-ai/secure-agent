//go:build darwin

package api

import "testing"

func TestDarwinPeerAuditVersion(t *testing.T) {
	a, b := socketpair(t)
	defer a.Close()
	defer b.Close()
	cred, err := NewPeerChecker().PeerCred(a)
	if err != nil || cred.PID <= 0 || cred.PIDVersion == 0 {
		t.Fatalf("missing kernel process instance: %+v, %v", cred, err)
	}
}
