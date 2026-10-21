package store

import (
	"context"
	"database/sql"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// rowQuerier lets history reuse the same decoders inside a read snapshot.
type rowQuerier interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

// Every query in a receipt snapshot inherits the request's deadline.
type contextRows struct {
	ctx context.Context
	db  interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}
}

func (q contextRows) Query(query string, args ...any) (*sql.Rows, error) {
	return q.db.QueryContext(q.ctx, query, args...)
}

func (q contextRows) QueryRow(query string, args ...any) *sql.Row {
	return q.db.QueryRowContext(q.ctx, query, args...)
}

type receiptReader struct {
	store *Store
	q     contextRows
}

func (r receiptReader) GuardDecisionHistory(id string, limit int) ([]GuardDecision, error) {
	return guardDecisionHistoryQuery(r.q, id, limit)
}

func (r receiptReader) ListSessionFindingReviews(id string) (ReviewPage, error) {
	// Receipt history carries evidence links, never current scope authority.
	return r.store.listFindingReviewsQuery(r.q, "", 100, "", id, false)
}

func (r receiptReader) RecentInterventions(id string, limit int) ([]model.InterventionReceipt, error) {
	return r.store.recentInterventionsQuery(r.q, id, limit)
}

func (r receiptReader) SessionIncidents(id string) (_ []model.IncidentReport, readErr error) {
	defer func() { r.store.noteRead("incident remediation", readErr) }()
	details, err := r.store.incidentDetailsQuery(r.q, `SELECT `+incidentDetailColumns+` FROM incidents WHERE session_id=? ORDER BY `+timestampOrderExpr("created_at")+` DESC,id DESC LIMIT 100`, id, id)
	if err != nil {
		return nil, err
	}
	out := make([]model.IncidentReport, len(details))
	for i := range details {
		out[i] = details[i].IncidentReport
	}
	return out, nil
}

func (s *Store) sessionOutcomesContext(ctx context.Context, id string) (_ SessionOutcomeHistory, readErr error) {
	defer func() { s.noteRead("receipt history", readErr) }()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return emptySessionOutcomes(), err
	}
	defer tx.Rollback()
	out := readSessionOutcomeHistory(receiptReader{s, contextRows{ctx, tx}}, id)
	return out, ctx.Err()
}
