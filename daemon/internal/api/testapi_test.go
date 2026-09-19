package api

import (
	"os"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// newTestAPI builds a minimal API from the positional essentials most tests
// need. Production wiring goes through api.New(api.Deps{...}); this keeps the
// tests readable without repeating the struct literal 60 times. Tests that
// need more components set the unexported fields directly (they are in-package).
func newTestAPI(sock string, st *store.Store, killer Killer, status StatusFunc) *API {
	return New(Deps{SocketPath: sock, Store: st, Killer: killer, Status: status})
}

// setPeersForTest mirrors the Deps peer wiring for tests that configure the
// gate after construction.
func (a *API) setPeersForTest(checker PeerChecker, agentPIDs func() map[int32]struct{}) {
	a.peerChk = checker
	a.agentPIDs = agentPIDs
	if checker != nil {
		a.peerRole = &peers{OwnerUID: os.Getuid(), AgentPIDs: agentPIDs}
	}
}

// setFirewallForTest assigns the firewall controls directly (in-package).
func (a *API) setFirewallForTest(c FirewallControl) {
	a.fwEngine = c.Engine
	a.fwModes = c.Modes
	a.fwReload = c.Reload
	a.fwIngest = c.Ingest
	a.fwSources = c.Sources
	a.fwBaseSources = c.BaseSources
}
