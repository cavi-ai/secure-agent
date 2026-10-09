package store

import (
	"context"
	"errors"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"testing"
	"time"
)

func scopeFixture(t *testing.T) (*Store, model.DecisionScope) {
	t.Helper()
	s := reviewStore(t)
	now := time.Now().UTC()
	if err := s.UpsertSession(model.Session{ID: "session", Harness: "codex", Workspace: "/work", RootPID: 42, RootStartedAt: now.Format(time.RFC3339Nano), StartedAt: now, LastSeenAt: now, Status: model.SessionActive}); err != nil {
		t.Fatal(err)
	}
	return s, model.DecisionScope{ID: "scope", Kind: "session", Agent: "codex", SessionID: "session", Workspace: "/work", ReaderExe: "/bin/cat", RuleID: "r", ResourcePath: "/work/.env", Operation: "guard:Read", CreatedAt: now, IdentityBasis: "peer-process-tree"}
}

func expectedReviewFixture(t *testing.T) (*Store, model.ReviewRecord) {
	s, _ := scopeFixture(t)
	f := reviewFlag("source")
	f.Evidence[0].Exe = "/bin/cat"
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveFindingReview(f, model.AssessFinding(f)); err != nil {
		t.Fatal(err)
	}
	return s, onlyReview(t, s)
}

func TestScopeStaleRevision(t *testing.T) {
	s, r := expectedReviewFixture(t)
	_, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision + 1, Action: "expect", Scope: &model.ScopeChoice{Kind: "session"}})
	if !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("stale decision: %v", err)
	}
	grants, err := s.ListDecisionScopes()
	if err != nil || len(grants) != 0 {
		t.Fatalf("stale decision granted: %v %v", grants, err)
	}
}

func TestReviewScopeTransactionAndIdempotency(t *testing.T) {
	s, r := expectedReviewFixture(t)
	req := model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "expect", Scope: &model.ScopeChoice{Kind: "exact", Expiry: "24h"}}
	first, err := s.DecideFindingReview(req)
	if err != nil || len(first.ScopeIDs) != 1 {
		t.Fatalf("create: %+v %v", first, err)
	}
	replay, err := s.DecideFindingReview(req)
	if err != nil || !replay.At.Equal(first.At) || replay.ScopeIDs[0] != first.ScopeIDs[0] {
		t.Fatalf("replay extended grant: %+v %v", replay, err)
	}
	if err = s.RevokeDecisionScope(first.ScopeIDs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DecideFindingReview(req); err != nil {
		t.Fatal(err)
	}
	grants, err := s.ListDecisionScopes()
	if err != nil || len(grants) != 1 || grants[0].RevokedAt.IsZero() {
		t.Fatal("replay reactivated revoked scope")
	}
	req.Scope.Expiry = "7d"
	if _, err = s.DecideFindingReview(req); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("changed replay: %v", err)
	}
}

func TestReviewScopeFailureRollsBackReceiptAndAcknowledgement(t *testing.T) {
	s, r := expectedReviewFixture(t)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_receipt BEFORE INSERT ON finding_review_actions BEGIN SELECT RAISE(FAIL,'receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "expect", Scope: &model.ScopeChoice{Kind: "session"}})
	if err == nil {
		t.Fatal("receipt failure ignored")
	}
	g, e := s.ListDecisionScopes()
	if e != nil || len(g) != 0 {
		t.Fatalf("failed receipt left grant: %v %v", g, e)
	}
	f, _ := s.GetFlag("source")
	if f.Acknowledged {
		t.Fatal("failed transaction acknowledged source")
	}
	if onlyReview(t, s).ReviewState != "unreviewed" {
		t.Fatal("failed transaction reviewed source")
	}
}

func saveScope(t *testing.T, s *Store, g model.DecisionScope) {
	t.Helper()
	commit, rollback, err := s.PrepareDecisionScope(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback()
	if err = commit(); err != nil {
		t.Fatal(err)
	}
}

func TestScopeDoesNotCrossSession(t *testing.T) {
	s, g := scopeFixture(t)
	saveScope(t, s, g)
	if !s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("grant not active after commit")
	}
	q := g
	q.SessionID = "other"
	if s.MatchDecisionScopes([]model.DecisionScope{q}) {
		t.Fatal("grant crossed session")
	}
	if err := s.EndSession("session", time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("ended session reused grant")
	}
}

func TestScopeExpiry(t *testing.T) {
	s, g := scopeFixture(t)
	g.Kind = "exact"
	g.ExpiresAt = time.Now().Add(100 * time.Millisecond)
	saveScope(t, s, g)
	if !s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("grant not initially active")
	}
	time.Sleep(time.Until(g.ExpiresAt))
	if s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("cached grant survived expiry")
	}
}

func TestScopeRetentionPreservesActivePermissions(t *testing.T) {
	s, g := scopeFixture(t)
	g.ID = "active"
	g.CreatedAt = time.Now().Add(-40 * 24 * time.Hour)
	saveScope(t, s, g)
	old := g
	old.ID = "expired"
	old.Kind = "exact"
	old.ExpiresAt = old.CreatedAt.Add(24 * time.Hour)
	saveScope(t, s, old)
	g.ID = "new"
	g.CreatedAt = time.Now()
	saveScope(t, s, g)
	rows, err := s.ListDecisionScopes()
	if err != nil || len(rows) != 2 {
		t.Fatalf("terminal permission cleanup: %v %v", rows, err)
	}
	for _, row := range rows {
		if row.ID == "expired" {
			t.Fatal("expired permission occupied capacity after retention")
		}
	}
	if !s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("retention removed a live session permission")
	}
}

func TestScopeRevocation(t *testing.T) {
	s, g := scopeFixture(t)
	saveScope(t, s, g)
	if err := s.RevokeDecisionScope(g.ID); err != nil {
		t.Fatal(err)
	}
	if s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("cached grant survived revocation")
	}
}

func TestScopeUnknownSessionStatusFailsClosed(t *testing.T) {
	s, g := scopeFixture(t)
	saveScope(t, s, g)
	if _, err := s.db.Exec(`UPDATE sessions SET status='unknown' WHERE id='session'`); err != nil {
		t.Fatal(err)
	}
	if s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("unknown lifecycle inherited reusable permission")
	}
}

func TestGuardGrantDoesNotPermitEgress(t *testing.T) {
	s, g := scopeFixture(t)
	saveScope(t, s, g)
	q := g
	q.Operation = "read-connect"
	q.Destination = "example.com:443"
	if s.MatchDecisionScopes([]model.DecisionScope{q}) {
		t.Fatal("file grant authorized egress")
	}
}

func TestScopeWriteFailureDoesNotGrant(t *testing.T) {
	s, g := scopeFixture(t)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_scope BEFORE INSERT ON decision_scopes BEGIN SELECT RAISE(FAIL,'write failure'); END`); err != nil {
		t.Fatal(err)
	}
	_, rollback, err := s.PrepareDecisionScope(context.Background(), g)
	if rollback != nil {
		rollback()
	}
	if err == nil {
		t.Fatal("failed save reported success")
	}
	if s.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("failed write activated grant")
	}
}
