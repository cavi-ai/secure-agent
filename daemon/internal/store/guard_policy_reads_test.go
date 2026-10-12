package store

import (
	"strings"
	"testing"
)

func TestGuardPolicyListsRejectUnavailableAndPartialReads(t *testing.T) {
	for _, kind := range []string{"rules", "paths"} {
		for _, fault := range []string{"empty", "closed", "scan"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				s, err := Open("", "")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.Close() })
				if fault == "closed" {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if fault == "scan" {
					// A valid newest record precedes a legacy nullable field that
					// cannot be decoded. The read must discard the valid prefix.
					query := `INSERT INTO guard_rules(agent,rule_id,decision,source,created_at) VALUES
						('claude','valid','deny','prompt','2026-10-02T00:00:00Z'),
						('claude','invalid','allow',NULL,'2026-10-01T00:00:00Z')`
					if kind == "paths" {
						query = `INSERT INTO guard_path_allows(agent,rule_id,path,created_at) VALUES
							('claude','valid','/synthetic/new','2026-10-02T00:00:00Z'),
							('claude','invalid','/synthetic/old',NULL)`
					}
					if _, err := s.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				var count int
				var nilRows bool
				if kind == "rules" {
					rows, readErr := s.ListGuardRules(200)
					count, nilRows, err = len(rows), rows == nil, readErr
				} else {
					rows, readErr := s.ListGuardPathAllows(200)
					count, nilRows, err = len(rows), rows == nil, readErr
				}
				if fault == "empty" {
					if err != nil || nilRows || count != 0 {
						t.Fatalf("empty read: count=%d nil=%v err=%v", count, nilRows, err)
					}
				} else if err == nil || !nilRows || count != 0 {
					t.Fatalf("failed read: count=%d nil=%v err=%v", count, nilRows, err)
				} else if fault == "scan" && !strings.Contains(err.Error(), "scan guard") {
					t.Fatalf("scan error lost: %v", err)
				}
			})
		}
	}
}
