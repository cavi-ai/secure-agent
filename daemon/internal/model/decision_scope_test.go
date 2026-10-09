package model

import (
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
