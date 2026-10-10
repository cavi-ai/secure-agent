package store

import (
	"errors"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestReviewMembershipRejectsForeignContextBeforeDecisions(t *testing.T) {
	for _, variant := range []string{"resource", "destination", "session", "unknown"} {
		for _, action := range []string{"acknowledge", "close_reported", "expect"} {
			t.Run(variant+"/"+action, func(t *testing.T) {
				s := reviewStore(t)
				first := reviewFlag("first")
				if variant == "unknown" {
					first.SessionID = ""
				}
				if _, err := s.PutFlag(first); err != nil {
					t.Fatal(err)
				}
				second := first
				second.ID = "second"
				second.Evidence = append([]model.EvidenceItem(nil), first.Evidence...)
				switch variant {
				case "resource":
					second.Evidence[0].Label = "/work/other"
				case "destination":
					second.Evidence[1].Label = "203.0.113.6:443"
				case "session":
					second.SessionID = "other"
					if err := s.UpsertSession(model.Session{ID: "other", Confidence: model.ConfHook}); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := s.PutFlag(second); err != nil {
					t.Fatal(err)
				}
				firstID, err := s.FindingReviewID(first.ID)
				if err != nil {
					t.Fatal(err)
				}
				secondID, err := s.FindingReviewID(second.ID)
				if err != nil || firstID == "" || secondID == "" || firstID == secondID {
					t.Fatalf("independent reviews required: %q %q %v", firstID, secondID, err)
				}
				var before string
				if err := s.db.QueryRow(`SELECT record_json FROM finding_reviews WHERE id=?`, firstID).Scan(&before); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`UPDATE finding_review_members SET review_id=? WHERE flag_id=?`, firstID, second.ID); err != nil {
					t.Fatal(err)
				}
				if id, err := s.FindingReviewID(second.ID); err == nil || id != "" {
					t.Errorf("foreign context returned a link: %q %v", id, err)
				}
				if _, found, err := s.GetFindingReview(firstID); err == nil || found {
					t.Errorf("foreign context served as valid review detail: found=%v err=%v", found, err)
				}
				req := model.ReviewDecisionRequest{ID: firstID, Revision: 1, Action: action}
				if action == "expect" {
					req.Scope = &model.ScopeChoice{Kind: "once"}
				}
				if _, err := s.DecideFindingReview(req); !errors.Is(err, ErrReviewConflict) {
					t.Errorf("foreign-context %s decision: %v", action, err)
				}
				for _, query := range []string{`SELECT COUNT(*) FROM flags WHERE COALESCE(acknowledged,'')!=''`, `SELECT COUNT(*) FROM finding_review_actions`, `SELECT COUNT(*) FROM decision_scope_receipts`, `SELECT COUNT(*) FROM decision_scopes`} {
					var n int
					if err := s.db.QueryRow(query).Scan(&n); err != nil || n != 0 {
						t.Errorf("foreign-context decision wrote state: query=%s count=%d err=%v", query, n, err)
					}
				}
				var after string
				if err := s.db.QueryRow(`SELECT record_json FROM finding_reviews WHERE id=?`, firstID).Scan(&after); err != nil || after != before {
					t.Errorf("foreign-context decision changed canonical record: %v", err)
				}
				if _, err := s.db.Exec(`UPDATE finding_review_members SET review_id=? WHERE flag_id=?`, secondID, second.ID); err != nil {
					t.Fatal(err)
				}
				if id, err := s.FindingReviewID(second.ID); err != nil || id != secondID {
					t.Errorf("membership repair failed: %q %v", id, err)
				}
				if _, found, err := s.GetFindingReview(firstID); err != nil || !found {
					t.Errorf("review detail failed to recover: found=%v err=%v", found, err)
				}
			})
		}
	}
}

func TestReviewMembershipPreservesPromotionCollisionDecisions(t *testing.T) {
	s := reviewStore(t)
	if err := s.UpsertSession(model.Session{ID: "canonical", Confidence: model.ConfHook}); err != nil {
		t.Fatal(err)
	}
	f := reviewFlag("old")
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	oldID, err := s.FindingReviewID(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.ID, f.SessionID = "canonical-source", "canonical"
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	canonicalID, err := s.FindingReviewID(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RekeySession("session", "canonical"); err != nil {
		t.Fatal(err)
	}
	for flagID, reviewID := range map[string]string{"old": oldID, "canonical-source": canonicalID} {
		if id, err := s.FindingReviewID(flagID); err != nil || id != reviewID {
			t.Fatalf("promotion link: %q %v", id, err)
		}
		r, found, err := s.GetFindingReview(reviewID)
		if err != nil || !found {
			t.Fatalf("promotion detail: found=%v err=%v", found, err)
		}
		if _, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: reviewID, Revision: r.Revision, Action: "acknowledge"}); err != nil {
			t.Fatalf("promotion decision: %v", err)
		}
	}
}
