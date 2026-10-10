package store

import (
	"slices"
	"testing"
)

func TestFindingReviewLinkRejectsUnavailableTargetsAndRecovers(t *testing.T) {
	for _, damage := range []string{
		`DELETE FROM finding_reviews WHERE id=?`,
		`UPDATE finding_reviews SET record_json='invalid' WHERE id=?`,
		`UPDATE finding_reviews SET record_json='null' WHERE id=?`,
		`UPDATE finding_reviews SET record_json=json_set(record_json,'$.id','wrong') WHERE id=?`,
		`UPDATE finding_reviews SET state='closed_reported' WHERE id=?`,
	} {
		t.Run(damage, func(t *testing.T) {
			s := reviewStore(t)
			f := reviewFlag("source")
			if _, err := s.PutFlag(f); err != nil {
				t.Fatal(err)
			}
			r := onlyReview(t, s)
			if _, err := s.db.Exec(`CREATE TEMP TABLE original_review AS SELECT * FROM finding_reviews`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(damage, r.ID); err != nil {
				t.Fatal(err)
			}
			if id, err := s.FindingReviewID(f.ID); err == nil || id != "" {
				t.Errorf("unavailable target returned a usable link: id=%q err=%v", id, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"finding reviews"}) || h.Failures != 0 {
				t.Errorf("review link read failure hidden: %+v", h)
			}
			if fl, found := s.GetFlagWithAdvisor(f.ID); !found || fl.ID != f.ID || fl.ReviewID != "" || len(fl.Evidence) != len(f.Evidence) {
				t.Errorf("delta lost core evidence or retained invalid link: %+v found=%v", fl, found)
			}
			if _, err := s.db.Exec(`DELETE FROM finding_reviews`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`INSERT INTO finding_reviews SELECT * FROM original_review`); err != nil {
				t.Fatal(err)
			}
			if id, err := s.FindingReviewID(f.ID); err != nil || id != r.ID {
				t.Fatalf("link recovery: %q %v", id, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 2 || len(h.ReadActive) != 0 {
				t.Errorf("recovery lost read history: %+v", h)
			}
		})
	}
}

func TestFindingReviewLinkScanFailureReturnsNoPartialID(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("source")
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE finding_review_members RENAME TO original_members`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE VIEW finding_review_members AS SELECT flag_id,review_id,NULL AS source_key FROM original_members`); err != nil {
		t.Fatal(err)
	}
	if id, err := s.FindingReviewID(f.ID); err == nil || id != "" {
		t.Fatalf("partial ID after scan failure: %q %v", id, err)
	}
}
