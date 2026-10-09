package store

import (
	"encoding/json"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestReviewIntegrityRejectsReadsAndDecisions(t *testing.T) {
	for _, damage := range []string{"null", "empty", "identity", "zero revision", "negative revision", "state mismatch", "invalid state"} {
		t.Run(damage, func(t *testing.T) {
			s := reviewStore(t)
			f := reviewFlag("first-integrity")
			if _, err := s.PutFlag(f); err != nil {
				t.Fatal(err)
			}
			first := onlyReview(t, s)
			g := reviewFlag("second-integrity")
			g.Workspace = "/other"
			if _, err := s.PutFlag(g); err != nil {
				t.Fatal(err)
			}
			page, err := s.ListFindingReviews("", 100)
			if err != nil || len(page.Reviews) != 2 {
				t.Fatalf("fixture: %+v %v", page, err)
			}
			var second model.ReviewRecord
			for _, r := range page.Reviews {
				if r.ID != first.ID {
					second = r
				}
			}
			var firstRaw, secondRaw string
			if err := s.db.QueryRow("SELECT record_json FROM finding_reviews WHERE id=?", first.ID).Scan(&firstRaw); err != nil {
				t.Fatal(err)
			}
			if err := s.db.QueryRow("SELECT record_json FROM finding_reviews WHERE id=?", second.ID).Scan(&secondRaw); err != nil {
				t.Fatal(err)
			}
			r := first
			state := "unreviewed"
			switch damage {
			case "identity":
				r = second
			case "zero revision":
				r.Revision = 0
			case "negative revision":
				r.Revision = -1
			case "state mismatch":
				r.ReviewState = "reviewed"
			case "invalid state":
				r.ReviewState, state = "invalid", "invalid"
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if damage == "null" {
				raw = []byte("null")
			}
			if damage == "empty" {
				raw = []byte("{}")
			}
			if _, err := s.db.Exec("UPDATE finding_reviews SET record_json=?,state=? WHERE id=?", string(raw), state, first.ID); err != nil {
				t.Fatal(err)
			}
			if got, found, err := s.GetFindingReview(first.ID); err == nil || found || got.ID != "" {
				t.Errorf("corrupt detail accepted: %+v found=%v err=%v", got, found, err)
			}
			if got, err := s.ListFindingReviews("", 100); err == nil || !got.Degraded || len(got.Reviews) != 0 || got.Next != "" {
				t.Errorf("corrupt list accepted or returned partial records: %+v %v", got, err)
			}
			if receipt, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: first.ID, Revision: first.Revision, Action: "acknowledge"}); err == nil || receipt.ID != "" {
				t.Errorf("corrupt record drove a decision: %+v %v", receipt, err)
			}
			for _, id := range []string{f.ID, g.ID} {
				if flag, found := s.GetFlag(id); !found || flag.Acknowledged {
					t.Errorf("failed decision acknowledged source %s: %+v", id, flag)
				}
			}
			var actions int
			if err := s.db.QueryRow("SELECT COUNT(*) FROM finding_review_actions").Scan(&actions); err != nil || actions != 0 {
				t.Errorf("failed decision wrote receipts: %d %v", actions, err)
			}
			var retained string
			if err := s.db.QueryRow("SELECT record_json FROM finding_reviews WHERE id=?", second.ID).Scan(&retained); err != nil || retained != secondRaw {
				t.Errorf("decision changed another review: %v", err)
			}
			if _, err := s.db.Exec("UPDATE finding_reviews SET record_json=?,state='unreviewed' WHERE id=?", firstRaw, first.ID); err != nil {
				t.Fatal(err)
			}
			if got, found, err := s.GetFindingReview(first.ID); err != nil || !found || got.ID != first.ID {
				t.Errorf("detail recovery: %+v %v %v", got, found, err)
			}
			if got, err := s.ListFindingReviews("", 100); err != nil || len(got.Reviews) != 2 {
				t.Errorf("list recovery: %+v %v", got, err)
			}
			if h := s.WriteHealth(); h.ReadFailures < 2 || len(h.ReadActive) != 0 {
				t.Errorf("read failure/recovery health: %+v", h)
			}
		})
	}
}

func TestReviewIntegrityBlocksSessionPromotion(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("promotion-integrity")
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	r := onlyReview(t, s)
	if _, err := s.db.Exec("UPDATE finding_reviews SET record_json='null' WHERE id=?", r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RekeySession("session", "canonical"); err == nil {
		t.Error("corrupt review allowed session promotion")
	}
	var sourceSession, retained string
	if err := s.db.QueryRow("SELECT session_id FROM flags WHERE id=?", f.ID).Scan(&sourceSession); err != nil || sourceSession != "session" {
		t.Errorf("failed promotion moved source: %q %v", sourceSession, err)
	}
	if err := s.db.QueryRow("SELECT record_json FROM finding_reviews WHERE id=?", r.ID).Scan(&retained); err != nil || retained != "null" {
		t.Errorf("failed promotion rewrote corrupt evidence: %q %v", retained, err)
	}
}
