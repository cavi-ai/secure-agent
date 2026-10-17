package apiroutes

import (
	"slices"
	"testing"
)

var allMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

// concretePaths are the request paths one route serves: its path, one id
// under each leaf of a prefix family, or a path inside a leafless subtree.
func concretePaths(r Route) []string {
	switch {
	case !r.Prefix:
		return []string{r.Path}
	case len(r.Leaves) == 0:
		return []string{r.Path + "inside"}
	}
	var out []string
	for _, leaf := range r.Leaves {
		out = append(out, r.Path+"id1/"+leaf.Path)
	}
	return out
}

// Every route's declared fields decide every predicate, for every method:
// the console admits GET and HEAD on console routes and only the methods a
// route lists; mutations, agent exclusion and the decide endpoint follow the
// route that serves the path.
func TestEveryRouteClassifiesEveryMethod(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Table {
		if seen[r.Path] {
			t.Errorf("%s appears twice; the first entry hides the second", r.Path)
		}
		seen[r.Path] = true
		if len(r.Leaves) > 0 && !r.Prefix || r.Prefix && len(r.Leaves) == 0 && !r.OwnerOnly {
			t.Errorf("%s: prefix %v with %d leaves; only an owner-only subtree has none", r.Path, r.Prefix, len(r.Leaves))
		}
		if r.OwnerOnly && (r.Console || len(r.MutatingMethods) > 0 || len(r.ConsoleMethods) > 0) {
			t.Errorf("%s: owner-only routes are never console routes", r.Path)
		}
		if len(r.ConsoleMethods) > 0 && !r.Console {
			t.Errorf("%s: console methods on a route the console cannot reach", r.Path)
		}
		for _, m := range r.ConsoleMethods {
			if m == "GET" || m == "HEAD" {
				t.Errorf("%s: %s is admitted on every console route; listing it says nothing", r.Path, m)
			}
		}
		for _, m := range r.MutatingMethods {
			if m == "GET" || m == "HEAD" || slices.Contains(r.ConsoleMethods, m) {
				t.Errorf("%s: %s cannot be a pinned-UI mutation here", r.Path, m)
			}
		}
		for _, path := range concretePaths(r) {
			if got := IsNoAgent(path); got != r.NoAgent {
				t.Errorf("IsNoAgent(%s) = %v, want %v", path, got, r.NoAgent)
			}
			if got := IsOwnerOnly(path); got != r.OwnerOnly {
				t.Errorf("IsOwnerOnly(%s) = %v, want %v", path, got, r.OwnerOnly)
			}
			for _, m := range allMethods {
				read := m == "GET" || m == "HEAD"
				wantConsole := r.Console && (read || slices.Contains(r.MutatingMethods, m) || slices.Contains(r.ConsoleMethods, m))
				if got := ConsoleAllowed(m, path); got != wantConsole {
					t.Errorf("ConsoleAllowed(%s %s) = %v, want %v", m, path, got, wantConsole)
				}
				if got, want := IsMutation(m, path), slices.Contains(r.MutatingMethods, m); got != want {
					t.Errorf("IsMutation(%s %s) = %v, want %v", m, path, got, want)
				}
				if got, want := IsDecide(m, path), m == "POST" && r.Decide; got != want {
					t.Errorf("IsDecide(%s %s) = %v, want %v", m, path, got, want)
				}
			}
		}
	}
}

// Paths outside the table, and malformed ids under a prefix family, match no
// route: the console refuses them and no route policy applies.
func TestUnknownPathsMatchNoRoute(t *testing.T) {
	var paths []string
	for _, r := range Table {
		if r.Prefix && len(r.Leaves) > 0 {
			paths = append(paths, r.Path+"../"+r.Leaves[0].Path, r.Path+"./"+r.Leaves[0].Path,
				r.Path+"/"+r.Leaves[0].Path, r.Path+"id1/not-a-leaf")
		}
	}
	paths = append(paths, "/not-a-route", "/status/extra", "")
	for _, path := range paths {
		for _, m := range allMethods {
			if ConsoleAllowed(m, path) || IsMutation(m, path) || IsDecide(m, path) {
				t.Errorf("%s %s matched a route", m, path)
			}
		}
		if IsNoAgent(path) {
			t.Errorf("IsNoAgent(%s) matched a route", path)
		}
	}
}
