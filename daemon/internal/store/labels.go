package store

import (
	"fmt"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// PutOperatorLabel records best-effort feedback from another control action.
// Explicit operator judgments use PutOperatorLabelResult to observe failures.
func (s *Store) PutOperatorLabel(l model.OperatorLabel) {
	if err := s.PutOperatorLabelResult(l); err != nil {
		log.Printf("store: operator label: %v", err)
	}
}

// PutOperatorLabelResult commits one judgment and trims history atomically,
// keeping the newest maxOperatorLabels. An error leaves history unchanged.
func (s *Store) PutOperatorLabelResult(l model.OperatorLabel) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.noteWrite("operator labels", err) }()
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin operator label write: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO operator_labels (kind, rule, agent, pattern, label, reason, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, l.Kind, l.Rule, l.Agent, l.Pattern, l.Label, l.Reason, l.Source,
		l.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("insert operator label: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM operator_labels WHERE id NOT IN
		(SELECT id FROM operator_labels ORDER BY id DESC LIMIT ?)`, maxOperatorLabels); err != nil {
		return fmt.Errorf("trim operator labels: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operator label write: %w", err)
	}
	return nil
}

// SimilarLabels returns up to limit labels sharing the rule or the pattern,
// ranked: the exact case, the same agent and pattern, the same rule and
// agent, the same pattern, the same rule; newest first within a rank. Empty
// keys match nothing. Never nil.
func (s *Store) SimilarLabels(rule, agent, pattern string, limit int) []model.OperatorLabel {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.OperatorLabel{}
	rows, err := s.db.Query(`SELECT id, kind, rule, agent, pattern, label, reason, source, created_at FROM operator_labels
		WHERE (? != '' AND rule = ?) OR (? != '' AND pattern = ?)
		ORDER BY CASE
			WHEN rule = ? AND agent = ? AND pattern = ? THEN 5
			WHEN agent = ? AND pattern = ? THEN 4
			WHEN rule = ? AND agent = ? THEN 3
			WHEN pattern = ? THEN 2
			ELSE 1 END DESC, id DESC
		LIMIT ?`,
		rule, rule, pattern, pattern,
		rule, agent, pattern,
		agent, pattern,
		rule, agent,
		pattern,
		normalizeLimit(limit))
	if err != nil {
		log.Printf("store: similar labels: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var l model.OperatorLabel
		var ts string
		if rows.Scan(&l.ID, &l.Kind, &l.Rule, &l.Agent, &l.Pattern, &l.Label, &l.Reason, &l.Source, &ts) != nil {
			continue
		}
		l.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: similar labels cursor: %v", err)
	}
	return out
}

// LabelSummary counts ok and not_ok labels on the same case: the same agent
// and pattern, or the same rule and agent when there is no pattern.
func (s *Store) LabelSummary(agent, pattern, rule string) model.LabelSummary {
	var sum model.LabelSummary
	if pattern == "" && rule == "" {
		return sum
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q := `SELECT COALESCE(SUM(label = 'ok'), 0), COALESCE(SUM(label = 'not_ok'), 0) FROM operator_labels WHERE agent = ? AND pattern = ?`
	args := []any{agent, pattern}
	if pattern == "" {
		q = `SELECT COALESCE(SUM(label = 'ok'), 0), COALESCE(SUM(label = 'not_ok'), 0) FROM operator_labels WHERE rule = ? AND agent = ? AND pattern = ''`
		args = []any{rule, agent}
	}
	if err := s.db.QueryRow(q, args...).Scan(&sum.OK, &sum.NotOK); err != nil {
		log.Printf("store: label summary: %v", err)
	}
	return sum
}
