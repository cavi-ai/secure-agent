package api

import (
	"slices"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
)

// Across every route, method and role, with and without a pinned UI:
// unidentified and foreign peers reach nothing; agents only read and ask for
// their own guard decision, never on a no-agent or owner-only route; the
// owner loses only the mutations a pinned UI holds; the pinned UI reaches
// everything.
func TestAuthorizeAcrossRolesMethodsAndRouteClasses(t *testing.T) {
	methods := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
	for _, pinned := range []bool{false, true} {
		a := &API{peerRole: &peers{OwnerUID: 501}}
		if pinned {
			a.peerRole.UIPID = 4242
		}
		for _, r := range apiroutes.Table {
			paths := []string{r.Path}
			if r.Prefix {
				paths = nil
				if len(r.Leaves) == 0 { // an owner-only subtree
					paths = []string{r.Path + "inside"}
				}
				for _, leaf := range r.Leaves {
					paths = append(paths, r.Path+"id1/"+leaf.Path)
				}
			}
			for _, path := range paths {
				for _, m := range methods {
					mutation := slices.Contains(r.MutatingMethods, m)
					decide := m == "POST" && r.Decide
					want := map[role]bool{
						roleNone:    false,
						roleForeign: false,
						roleAgent:   !r.NoAgent && !r.OwnerOnly && (decide || m == "GET" && !mutation),
						roleOwner:   decide || !(pinned && mutation),
						roleUI:      true,
					}
					for ro, ok := range want {
						if got := a.authorize(ro, m, path); got != ok {
							t.Errorf("pinned UI %v: %s %s for %s = %v, want %v", pinned, m, path, ro, got, ok)
						}
					}
				}
			}
		}
	}
}
