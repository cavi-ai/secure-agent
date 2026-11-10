package api

import "testing"

func TestPeerRoleRequiresUIDAndPinnedInstance(t *testing.T) {
	p := peers{OwnerUID: 501, UIPID: 4242, UIPIDVersion: 7}
	for _, tc := range []struct {
		name string
		cred PeerCred
		want role
	}{
		{"pinned instance", PeerCred{PID: 4242, UID: 501, PIDVersion: 7}, roleUI},
		{"foreign uid", PeerCred{PID: 4242, UID: 502, PIDVersion: 7}, roleForeign},
		{"reused pid", PeerCred{PID: 4242, UID: 501, PIDVersion: 8}, roleForeign},
		{"unavailable version", PeerCred{PID: 4242, UID: 501}, roleForeign},
		{"closed peer", PeerCred{UID: 501}, roleNone},
		{"owner shell", PeerCred{PID: 999, UID: 501}, roleOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.classify(tc.cred); got != tc.want {
				t.Fatalf("role=%s, want %s", got, tc.want)
			}
		})
	}
}
