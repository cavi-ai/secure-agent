package correlate

import (
	"path/filepath"
	"testing"
)

// Workspace scopes match by path prefix (a scope on a repo covers anything
// under it) and the most specific scope wins — "prod pages, scratch quiet"
// must not be overridden by a broader parent scope.
func TestNotifyScopePrefixAndLongestWins(t *testing.T) {
	s := NewNotifyScopeStore(filepath.Join(t.TempDir(), "scopes.json"))

	if err := s.Set("/Users/dev/work", "proxy-secret-leak", true); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("/Users/dev/work/scratch", "proxy-secret-leak", false); err != nil {
		t.Fatal(err)
	}

	// Exact + descendant both covered by the broad scope.
	if v, ok := s.Lookup("/Users/dev/work/prod-api", "proxy-secret-leak"); !ok || v != true {
		t.Fatalf("descendant lookup = %v,%v want true", v, ok)
	}
	// The more specific scope wins under it.
	if v, ok := s.Lookup("/Users/dev/work/scratch/clone", "proxy-secret-leak"); !ok || v != false {
		t.Fatalf("longest-prefix lookup = %v,%v want false", v, ok)
	}
	// A different rule is unaffected by another rule's scope.
	if _, ok := s.Lookup("/Users/dev/work/prod-api", "keychain-access"); ok {
		t.Fatal("scope leaked across rules")
	}
	// Outside the scope: no decision.
	if _, ok := s.Lookup("/Users/other/repo", "proxy-secret-leak"); ok {
		t.Fatal("unrelated workspace matched")
	}
	// A sibling path with a shared string prefix is not a descendant.
	if _, ok := s.Lookup("/Users/dev/workbench", "proxy-secret-leak"); ok {
		t.Fatal("string-prefix sibling must not match a path scope")
	}
}

func TestNotifyScopePersistsAndClears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scopes.json")
	s := NewNotifyScopeStore(path)
	if err := s.Set("/repo", "keychain-access", false); err != nil {
		t.Fatal(err)
	}
	// A second store on the same file sees it (persisted, atomic write).
	s2 := NewNotifyScopeStore(path)
	if v, ok := s2.Lookup("/repo/sub", "keychain-access"); !ok || v != false {
		t.Fatalf("reloaded scope = %v,%v", v, ok)
	}
	if err := s2.Clear("/repo", "keychain-access"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Lookup("/repo/sub", "keychain-access"); ok {
		t.Fatal("cleared scope still applies")
	}
	if n := len(s2.Pairs()); n != 0 {
		t.Fatalf("pairs after clear = %d, want 0", n)
	}
}
