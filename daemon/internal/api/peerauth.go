package api

import (
	"context"
	"net"
	"net/http"
	"os"
)

// Role of the authenticated peer on a control-socket connection.
type role int

const (
	roleNone    role = iota // peer could not be identified (non-unix conn, kernel refusal)
	roleForeign             // same machine, different uid — untrusted
	roleAgent               // a tagged agent process (hook traffic)
	roleOwner               // same uid as the daemon (user shells, CLI)
	roleUI                  // the menubar app (trusted mutating client)
)

// peers holds the process identities the API trusts. All fields are optional:
// when OwnerUID is nil every same-uid caller is trusted for reads; when
// UIPID/AgentPIDs are empty those roles simply never match.
type peers struct {
	OwnerUID  int
	UIPID     int32
	AgentPIDs func() map[int32]struct{} // live tagged-agent pid set, may be nil
}

// classify maps a kernel-attested peer to a role.
func (p *peers) classify(cred PeerCred) role {
	if cred.PID > 0 && cred.PID == p.UIPID {
		return roleUI
	}
	if p.AgentPIDs != nil {
		if _, ok := p.AgentPIDs()[cred.PID]; ok && cred.PID > 0 {
			return roleAgent
		}
	}
	if cred.PID == int32(os.Getpid()) {
		// Loopback from the daemon itself (e.g. its own fleet/proxy calls).
		return roleOwner
	}
	if cred.UID == p.OwnerUID {
		return roleOwner
	}
	if cred.PID == 0 && cred.UID == 0 {
		// Peer already closed; kernel reports zeros. Fail safe: owner-level
		// read access only if the default uid also matches, else foreign.
		if p.OwnerUID == 0 {
			return roleOwner
		}
		return roleForeign
	}
	return roleForeign
}

// canRead: status, flags, events, incidents, audit, fleet, guard pending, rules list.
func (r role) canRead() bool {
	return r == roleOwner || r == roleUI || r == roleAgent
}

// canDecide: a hook asking the guard for a decision on its own tool call.
func (r role) canDecide() bool {
	return r == roleAgent || r == roleUI || r == roleOwner
}

// canMutate: kill, guard resolve, guard rule revoke, firewall promote/ingest.
func (r role) canMutate() bool {
	return r == roleUI
}

// gate wraps mux with peer-credential enforcement. A nil checker leaves the
// API open (unit tests, or builds where peer creds are unavailable); production
// wiring in main.go always sets one.
func (a *API) gate(checker PeerChecker, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checker == nil {
			next.ServeHTTP(w, r)
			return
		}
		cred, err := checker.PeerCred(connOf(r))
		if err != nil {
			http.Error(w, "peer identification failed", http.StatusUnauthorized)
			return
		}
		role := a.peerRole.classify(cred)
		if !a.authorize(role, r.Method, r.URL.Path) {
			http.Error(w, "forbidden: this endpoint requires a more privileged client", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isMutation: POST on the mutating endpoint set (DELETE /guard/rules stays
// owner-level — headless fleets revoke cached decisions over ssh).
func isMutation(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	switch path {
	case "/kill", "/guard/resolve", "/guard/rules", "/firewall/mode",
		"/firewall/fingerprints/reload", "/firewall/fingerprints/ingest",
		"/firewall/sources", "/incidents/status":
		return true
	}
	return false
}

// authorize applies the (method, path) policy to a classified role. Reads are
// open to any identified local peer; decisions to any; mutations to the pinned
// menubar when one exists, otherwise to the owner uid (direct launches,
// headless/ssh management).
func (a *API) authorize(role role, method, path string) bool {
	if isMutation(method, path) && a.peerRole != nil && a.peerRole.UIPID > 0 {
		return role == roleUI
	}
	// Everything else (and all mutations when no UI pin exists) is owner-level.
	return role >= roleOwner
}

// peerConnKey is the context key under which the gate stores the request's
// underlying connection, provided via the server's ConnContext hook.
type peerConnKey struct{}

// connOf returns the connection a request arrived on (nil if absent).
func connOf(r *http.Request) net.Conn {
	if c, ok := r.Context().Value(peerConnKey{}).(net.Conn); ok {
		return c
	}
	return nil
}

// gateConnContext is applied as the server's ConnContext so each request's
// context carries the underlying connection.
func gateConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, peerConnKey{}, c)
}
