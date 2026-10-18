package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/shellreview"
)

const shellReviewsSchema = `CREATE TABLE IF NOT EXISTS shell_reviews (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at TEXT NOT NULL,
 result_json TEXT NOT NULL
);`

// PutShellReview stores metadata only. One transaction bounds retention and
// publication together. Stored rows never authorize later commands.
func (s *Store) PutShellReview(r shellreview.Result) (err error) {
	defer func() { s.noteWrite("shell reviews", err) }()
	if r.ID == "" || r.At.IsZero() || (r.Mode != "observe" && r.Mode != "block") {
		return fmt.Errorf("invalid shell review")
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO shell_reviews(at,result_json) VALUES (?,?)`, r.At.UTC().Format(guardDecisionTimeLayout), string(data))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM shell_reviews WHERE id NOT IN (SELECT id FROM shell_reviews ORDER BY id DESC LIMIT 1000) OR at < ?`, time.Now().Add(-7*24*time.Hour).UTC().Format(guardDecisionTimeLayout))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecentShellReviews(limit int) (out []shellreview.Result, err error) {
	defer func() { s.noteRead("shell reviews", err) }()
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT result_json FROM shell_reviews WHERE at >= ? ORDER BY id DESC LIMIT ?`, time.Now().Add(-7*24*time.Hour).UTC().Format(guardDecisionTimeLayout), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out = []shellreview.Result{}
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		var r shellreview.Result
		if err = json.Unmarshal([]byte(data), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
