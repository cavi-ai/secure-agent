package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// PutOperatorLabel commits one judgment and trims history atomically,
// keeping the newest maxOperatorLabels. An error leaves history unchanged.
func (s *Store) PutOperatorLabel(l model.OperatorLabel) (err error) {
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

// SimilarLabels rejects incomplete history rather than returning the
// rows preceding a query, scan, cursor or timestamp failure.
func (s *Store) SimilarLabels(rule, agent, pattern string, limit int) (out []model.OperatorLabel, err error) {
	defer func() { s.noteRead("similar operator labels", err) }()
	out = []model.OperatorLabel{}
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
		return nil, fmt.Errorf("query similar operator labels: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var l model.OperatorLabel
		var ts string
		if err := rows.Scan(&l.ID, &l.Kind, &l.Rule, &l.Agent, &l.Pattern, &l.Label, &l.Reason, &l.Source, &ts); err != nil {
			return nil, fmt.Errorf("scan operator label: %w", err)
		}
		l.CreatedAt, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, errors.New("invalid operator label timestamp")
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate operator labels: %w", err)
	}
	return out, nil
}

// LabelSummary distinguishes an empty history from an unavailable read.
func (s *Store) LabelSummary(agent, pattern, rule string) (sum model.LabelSummary, err error) {
	if pattern == "" && rule == "" {
		return sum, nil
	}
	defer func() { s.noteRead("operator label summary", err) }()
	q := `SELECT COALESCE(SUM(label = 'ok'), 0), COALESCE(SUM(label = 'not_ok'), 0) FROM operator_labels WHERE agent = ? AND pattern = ?`
	args := []any{agent, pattern}
	if pattern == "" {
		q = `SELECT COALESCE(SUM(label = 'ok'), 0), COALESCE(SUM(label = 'not_ok'), 0) FROM operator_labels WHERE rule = ? AND agent = ? AND pattern = ''`
		args = []any{rule, agent}
	}
	if err := s.db.QueryRow(q, args...).Scan(&sum.OK, &sum.NotOK); err != nil {
		return model.LabelSummary{}, fmt.Errorf("read operator label summary: %w", err)
	}
	return sum, nil
}
