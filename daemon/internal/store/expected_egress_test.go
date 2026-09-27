package store

import (
	"path/filepath"
	"testing"
)

func TestExpectedEgressMatchingAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	scope := EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
	exact, err := s.CreateExpectedEgressRule(ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: "203.0.113.1", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.CreateExpectedEgressRule(ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: "203.0.113.1", Protocol: "tcp", Port: 443})
	if err != nil || again.ID != exact.ID {
		t.Fatalf("duplicate=%+v err=%v", again, err)
	}
	obs := EgressObservation{Scope: scope, Host: "203.0.113.1", Protocol: "tcp", Port: 443}
	if !s.ExpectedEgressMatch(obs) {
		t.Fatal("exact destination did not match")
	}
	obs.Port = 80
	if s.ExpectedEgressMatch(obs) {
		t.Fatal("different port matched exact rule")
	}
	obs.Port = 443
	obs.Protocol = "udp"
	if s.ExpectedEgressMatch(obs) {
		t.Fatal("different protocol matched exact rule")
	}
	broad, err := s.CreateExpectedEgressRule(ExpectedEgressRule{Agent: scope.Agent, Kind: "scope", ExePath: scope.ExePath, Harness: scope.Harness, Workspace: scope.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	obs.Host = "203.0.113.2"
	obs.Protocol = "tcp"
	if !s.ExpectedEgressMatch(obs) {
		t.Fatal("new destination in same complete scope did not match")
	}
	obs.Scope.Workspace = "/work/b"
	if s.ExpectedEgressMatch(obs) {
		t.Fatal("different workspace matched broad rule")
	}
	if err := s.RevokeExpectedEgressRule(broad.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	obs.Scope.Workspace = "/work/a"
	if s.ExpectedEgressMatch(obs) {
		t.Fatal("revoked broad rule matched after reopen")
	}
	if len(s.ListExpectedEgressRules()) != 2 {
		t.Fatal("rules not persisted")
	}
}

func TestExpectedEgressRejectsAmbiguousAndMalformedRules(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, rule := range []ExpectedEgressRule{
		{Agent: "claude", Kind: "scope", ExePath: "/usr/bin/claude", Harness: "claude"},
		{Agent: "claude", Kind: "destination", Host: "localhost", Protocol: "tcp", Port: 443},
		{Agent: "claude", Kind: "destination", Host: "https://example.com/path?token=x", Protocol: "tcp", Port: 443},
		{Agent: "claude", Kind: "destination", Host: "example.com", Protocol: "tcp", Port: 0},
		{Agent: "claude", Kind: "destination", Host: "example.com", Protocol: "http", Port: 443},
	} {
		if _, err := s.CreateExpectedEgressRule(rule); err == nil {
			t.Errorf("accepted malformed rule %+v", rule)
		}
	}
}

func TestExpectedEgressActiveRuleSurvivesRevokedHistoryLimit(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	active, err := s.CreateExpectedEgressRule(ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: "203.0.113.1", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 501; i++ {
		rule, err := s.CreateExpectedEgressRule(ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: "198.51.100.1", Protocol: "tcp", Port: i})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeExpectedEgressRule(rule.ID); err != nil {
			t.Fatal(err)
		}
	}
	found := false
	for _, rule := range s.ListExpectedEgressRules() {
		if rule.ID == active.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("active older rule hidden behind revoked history")
	}
}
