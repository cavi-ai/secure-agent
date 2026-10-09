package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// PutAdvisorPlan stores (or replaces) the plan for subject, keeping the
// newest maxAdvisorPlans with best-effort retention pruning. A nil error means
// the new plan was inserted successfully.
func (s *Store) PutAdvisorPlan(subject string, p model.AdvisorPlan) (writeErr error) {
	defer func() { s.noteWrite("advisor plans", writeErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal advisor plan: %w", err)
	}
	result, err := s.db.Exec(`INSERT OR REPLACE INTO advisor_plans (subject_id, plan_json, created_at) VALUES (?, ?, ?)`,
		subject, string(data), p.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("insert advisor plan: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("advisor plan rows affected: %w", err)
	}
	if inserted != 1 {
		return fmt.Errorf("advisor plan insert affected %d rows", inserted)
	}
	_, _ = s.db.Exec(`DELETE FROM advisor_plans WHERE subject_id NOT IN
		(SELECT subject_id FROM advisor_plans ORDER BY created_at DESC LIMIT ?)`, maxAdvisorPlans)
	return nil
}

// AdvisorPlanFor returns the stored plan for subject.
func (s *Store) AdvisorPlanFor(subject string) (model.AdvisorPlan, bool) {
	p, found, _ := s.AdvisorPlanResultFor(subject)
	return p, found
}

// AdvisorPlanResultFor distinguishes healthy absence from an unavailable or
// malformed stored plan. Failed reads never return partial plan content.
func (s *Store) AdvisorPlanResultFor(subject string) (plan model.AdvisorPlan, found bool, readErr error) {
	defer func() { s.noteRead("advisor plans", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	var data string
	var created sql.NullString
	err := s.db.QueryRow(`SELECT plan_json, created_at FROM advisor_plans WHERE subject_id = ?`, subject).Scan(&data, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AdvisorPlan{}, false, nil
	}
	if err != nil {
		return model.AdvisorPlan{}, false, err
	}
	var p *model.AdvisorPlan
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return model.AdvisorPlan{}, false, err
	}
	if p == nil {
		return model.AdvisorPlan{}, false, fmt.Errorf("null advisor plan")
	}
	// Older optional index timestamps may be absent. When present, they must
	// agree with the JSON timestamp used to serve this plan.
	if created.String != "" {
		at, err := time.Parse(time.RFC3339Nano, created.String)
		if err != nil {
			return model.AdvisorPlan{}, false, fmt.Errorf("invalid advisor plan timestamp: %w", err)
		}
		if !at.Equal(p.CreatedAt) {
			return model.AdvisorPlan{}, false, fmt.Errorf("advisor plan timestamp mismatch")
		}
	}
	return *p, true, nil
}

// RuleCounts counts flags of rule raised for agent in the 7 and 30 days
// before now.
func (s *Store) RuleCounts(rule, agent string, now time.Time) (last7, last30 int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d7 := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	d30 := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := s.db.QueryRow(ruleCountsSQL, d7, d30, rule, agent).Scan(&last7, &last30); err != nil {
		log.Printf("store: rule counts: %v", err)
	}
	return last7, last30
}
