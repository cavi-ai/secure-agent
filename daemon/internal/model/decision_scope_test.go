package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestScopeBoundaries(t *testing.T) {
	now := time.Now().UTC()
	s := DecisionScope{ID: "grant", Kind: "session", Agent: "codex", SessionID: "session", Workspace: "/work", ReaderExe: "/bin/cat", RuleID: "credentials", ResourcePath: "/work/.env", Operation: "guard:Read", CreatedAt: now, IdentityBasis: "peer-process-tree"}
	if !s.Matches(s, now) {
		t.Fatal("same request did not match")
	}
	for _, field := range []string{"session", "workspace", "reader", "path", "operation", "destination", "agent", "rule"} {
		q := s
		switch field {
		case "session":
			q.SessionID = "other"
		case "workspace":
			q.Workspace = "/other"
		case "reader":
			q.ReaderExe = "/other/cat"
		case "path":
			q.ResourcePath += "/child"
		case "operation":
			q.Operation = "read-connect"
		case "destination":
			q.Destination = "evil.example:443"
		case "agent":
			q.Agent = "other"
		case "rule":
			q.RuleID = "other"
		}
		if s.Matches(q, now) {
			t.Errorf("grant crossed %s boundary", field)
		}
	}
	s.Kind = "exact"
	s.ExpiresAt = now.Add(time.Hour)
	q := s
	q.SessionID = "other"
	if !s.Matches(q, now) {
		t.Fatal("explicit exact scope did not cover a new session with the same coordinates")
	}
	if s.Matches(q, s.ExpiresAt) {
		t.Fatal("expired grant matched")
	}
	s.RevokedAt = now
	if s.Matches(q, now) {
		t.Fatal("revoked grant matched")
	}
	if s.MismatchReason(q, now) != "The previous permission was revoked." {
		t.Fatal("revocation explanation missing")
	}
	s.RevokedAt = time.Time{}
	if s.MismatchReason(q, s.ExpiresAt) != "The previous permission expired." {
		t.Fatal("expiry explanation missing")
	}
	s.Kind = "session"
	if s.MismatchReason(q, now) != "This is a different session from the previous permission." {
		t.Fatal("session explanation missing")
	}
}

func TestScopeUnknownIdentityOnceOnly(t *testing.T) {
	s := DecisionScope{Kind: "exact", Agent: "codex", RuleID: "r", ResourcePath: "/secret", Operation: "guard:Read", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if s.Validate() == nil {
		t.Fatal("reusable scope accepted incomplete identity")
	}
	s.Kind = "once"
	if s.Validate() != nil {
		t.Fatal("once decision must support incomplete identity")
	}
	if s.Matches(s, time.Now()) {
		t.Fatal("once decision reused")
	}
}

func TestDecisionApplicability(t *testing.T) {
	must := func(s string) time.Time {
		t.Helper()
		parsed, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	now := must("2026-10-09T12:00:00Z")
	base := DecisionScope{Kind: "exact", Operation: "read-connect", CreatedAt: must("2026-10-09T11:00:00Z"), ExpiresAt: must("2026-10-10T12:00:00Z")}
	cases := []struct {
		name   string
		edit   func(*DecisionScope)
		label  string
		revoke bool
	}{
		{name: "revoked", edit: func(s *DecisionScope) { s.RevokedAt = must("2026-10-09T12:00:00Z") }, label: "Revoked"},
		{name: "future revoked_at", edit: func(s *DecisionScope) { s.RevokedAt = must("2026-10-09T13:00:00Z") }, label: "Revocation time unavailable or in the future; applicability unknown"},
		{name: "future created_at", edit: func(s *DecisionScope) {
			s.CreatedAt = must("2026-10-09T13:00:00Z")
			s.ExpiresAt = must("2026-10-10T13:00:00Z")
		}, label: "Creation time unavailable or in the future; applicability unknown"},
		{name: "bad operation", edit: func(s *DecisionScope) { s.Operation = "unknown" }, label: "Operation unavailable; applicability unknown"},
		{name: "exact expired", edit: func(s *DecisionScope) { s.ExpiresAt = must("2026-10-09T12:00:00Z") }, label: "Expired"},
		{name: "exact missing expiry", edit: func(s *DecisionScope) { s.ExpiresAt = time.Time{} }, label: "Expiry unavailable; applicability unknown"},
		{name: "session", edit: func(s *DecisionScope) { s.Kind = "session" }, label: "Session permission", revoke: true},
		{name: "unknown kind", edit: func(s *DecisionScope) { s.Kind = "weekly" }, label: "Permission kind unavailable; applicability unknown"},
		{name: "timed permission", edit: func(*DecisionScope) {}, label: "Timed permission", revoke: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := base
			tc.edit(&scope)
			got := scope.Applicability(now)
			if got.Label != tc.label || got.Revoke != tc.revoke {
				t.Fatalf("Applicability() = %+v, want label %q revoke %v", got, tc.label, tc.revoke)
			}
			raw, err := json.Marshal(scope)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "applicability") {
				t.Fatalf("stored scope JSON includes applicability: %s", raw)
			}
		})
	}
}
