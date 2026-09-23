package store

import (
	"encoding/json"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// PutAdvisorPlan stores (or replaces) the plan for subject, keeping the
// newest maxAdvisorPlans.
func (s *Store) PutAdvisorPlan(subject string, p model.AdvisorPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(p)
	if err != nil {
		log.Printf("store: advisor plan %s: %v", subject, err)
		return
	}
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO advisor_plans (subject_id, plan_json, created_at) VALUES (?, ?, ?)`,
		subject, string(data), p.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		log.Printf("store: advisor plan %s: %v", subject, err)
		return
	}
	_, _ = s.db.Exec(`DELETE FROM advisor_plans WHERE subject_id NOT IN
		(SELECT subject_id FROM advisor_plans ORDER BY created_at DESC LIMIT ?)`, maxAdvisorPlans)
}

// AdvisorPlanFor returns the stored plan for subject.
func (s *Store) AdvisorPlanFor(subject string) (model.AdvisorPlan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var data string
	if err := s.db.QueryRow(`SELECT plan_json FROM advisor_plans WHERE subject_id = ?`, subject).Scan(&data); err != nil {
		return model.AdvisorPlan{}, false
	}
	var p model.AdvisorPlan
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		log.Printf("store: advisor plan %s: %v", subject, err)
		return model.AdvisorPlan{}, false
	}
	return p, true
}

// RuleCounts counts flags of rule raised for agent in the 7 and 30 days
// before now.
func (s *Store) RuleCounts(rule, agent string, now time.Time) (last7, last30 int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d7 := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	d30 := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN datetime(ts) >= datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN datetime(ts) >= datetime(?) THEN 1 ELSE 0 END), 0)
		FROM flags WHERE rule = ? AND agent = ?`, d7, d30, rule, agent).Scan(&last7, &last30); err != nil {
		log.Printf("store: rule counts: %v", err)
	}
	return last7, last30
}
