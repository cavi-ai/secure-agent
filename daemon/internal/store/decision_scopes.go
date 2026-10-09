package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const decisionScopesSchema = `CREATE TABLE IF NOT EXISTS decision_scopes (
 id TEXT PRIMARY KEY, agent TEXT NOT NULL, rule_id TEXT NOT NULL,
 operation TEXT NOT NULL, record_json TEXT NOT NULL
); CREATE INDEX IF NOT EXISTS idx_decision_scope_match ON decision_scopes(agent,rule_id,operation);
 CREATE TABLE IF NOT EXISTS decision_scope_receipts (
 review_id TEXT NOT NULL, revision INTEGER NOT NULL, choice_json TEXT NOT NULL, ids_json TEXT NOT NULL,
 PRIMARY KEY(review_id,revision));`

// scopeSession checks the authoritative lifecycle at both creation and use.
// Rekeyed or removed sessions cannot silently transfer session permissions.
func scopeSession(q interface{ QueryRow(string, ...any) *sql.Row }, g model.DecisionScope) bool {
	var harness, workspace, status, started string
	var root int32
	err := q.QueryRow(`SELECT harness,workspace,status,root_pid,root_started_at FROM sessions WHERE id=?`, g.SessionID).Scan(&harness, &workspace, &status, &root, &started)
	at, e := time.Parse(time.RFC3339Nano, started)
	return err == nil && e == nil && !at.IsZero() && root > 0 && (status == model.SessionActive || status == model.SessionIdle) && harness == g.Agent && workspace == g.Workspace
}

func insertDecisionScope(tx *sql.Tx, g model.DecisionScope) error {
	if err := g.Validate(); err != nil {
		return err
	}
	if g.Kind == "once" {
		return fmt.Errorf("once decisions are receipts, not reusable grants")
	}
	if !scopeSession(tx, g) {
		return ErrReviewConflict
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM decision_scopes`).Scan(&count); err != nil {
		return err
	}
	if count >= 10000 {
		return fmt.Errorf("permission storage capacity reached")
	}
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO decision_scopes VALUES(?,?,?,?,?)`, g.ID, g.Agent, g.RuleID, g.Operation, string(b))
	return err
}

// Retain terminal permission evidence for thirty days without exhausting the
// bounded grant table over the lifetime of the installation. Receipts remain
// historical; replay never recreates expired or revoked permissions.
func pruneDecisionScopes(tx *sql.Tx) error {
	cutoff := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	_, err := tx.Exec(`DELETE FROM decision_scopes WHERE
 julianday(json_extract(record_json,'$.expires_at')) < julianday(?) OR
 julianday(json_extract(record_json,'$.revoked_at')) < julianday(?) OR
 (json_extract(record_json,'$.kind')='session' AND julianday(json_extract(record_json,'$.created_at'))<julianday(?)
 AND NOT EXISTS(SELECT 1 FROM sessions WHERE id=json_extract(decision_scopes.record_json,'$.session_id') AND status!='ended'))`, cutoff, cutoff, cutoff)
	return err
}

// PrepareDecisionScope reserves SQLite's writer outside the broker lock.
// Only the returned commit activates a grant; rollback is safe after commit.
// This lets the broker atomically check its deadline and publish the result.
func (s *Store) PrepareDecisionScope(ctx context.Context, g model.DecisionScope) (func() error, func(), error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	rollback := func() { _ = tx.Rollback() }
	if err = pruneDecisionScopes(tx); err != nil {
		rollback()
		return nil, nil, err
	}
	if err = insertDecisionScope(tx, g); err != nil {
		rollback()
		return nil, nil, err
	}
	return tx.Commit, rollback, nil
}

func (s *Store) MatchDecisionScopes(requests []model.DecisionScope) bool {
	if len(requests) == 0 || len(requests) > 128 {
		return false
	}
	// A coherent SQLite snapshot avoids combining a revoked permission with an
	// old session lifecycle. Use wall time, never a caller's event timestamp.
	first := requests[0]
	for _, q := range requests {
		if q.Agent != first.Agent || q.SessionID != first.SessionID || q.Workspace != first.Workspace || q.Operation != first.Operation || q.RuleID != first.RuleID || !model.ExactPath(q.ReaderExe) || !model.ExactPath(q.ResourcePath) {
			return false
		}
	}
	// One read statement joins lifecycle and permissions in a WAL snapshot.
	// Do not use the store's immediate writer transactions on this hot path.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT d.record_json,s.harness,s.workspace,s.status,s.root_pid,s.root_started_at FROM decision_scopes d JOIN sessions s ON s.id=? WHERE d.agent=? AND d.rule_id=? AND d.operation=?`, first.SessionID, first.Agent, first.RuleID, first.Operation)
	if err != nil {
		return false
	}
	defer rows.Close()
	now := time.Now().UTC()
	matched := make([]bool, len(requests))
	for rows.Next() {
		var raw, harness, workspace, status, started string
		var root int32
		var g model.DecisionScope
		if rows.Scan(&raw, &harness, &workspace, &status, &root, &started) != nil {
			return false
		}
		at, e := time.Parse(time.RFC3339Nano, started)
		if e != nil || at.IsZero() || root <= 0 || harness != first.Agent || (first.Workspace != "" && workspace != first.Workspace) || (status != model.SessionActive && status != model.SessionIdle) {
			return false
		}
		if json.Unmarshal([]byte(raw), &g) != nil {
			return false
		}
		for i, q := range requests {
			if q.Workspace == "" && q.Operation == "read-connect" {
				q.Workspace = workspace
			}
			matched[i] = matched[i] || g.Matches(q, now)
		}
	}
	if rows.Err() != nil {
		return false
	}
	for _, ok := range matched {
		if !ok {
			return false
		}
	}
	return true
}

func createReviewScopesTx(tx *sql.Tx, req model.ReviewDecisionRequest, sources []reviewSource, receipt *model.ReviewDecisionReceipt) error {
	ids := []string{}
	if err := pruneDecisionScopes(tx); err != nil {
		return err
	}
	if req.Scope.Kind != "once" {
		seen := map[string]bool{}
		for _, source := range sources {
			coordinates, err := model.ReadConnectScopes(source.flag)
			if err != nil {
				return ErrReviewConflict
			}
			for _, g := range coordinates {
				req.Scope.Apply(&g, receipt.At)
				b, _ := json.Marshal(g)
				hash := sha256.Sum256(append([]byte(fmt.Sprintf("%s:%d:", req.ID, req.Revision)), b...))
				g.ID = hex.EncodeToString(hash[:])
				if seen[g.ID] {
					continue
				}
				seen[g.ID] = true
				if len(ids) >= 128 {
					return fmt.Errorf("permission decision exceeds scope limit")
				}
				if err = insertDecisionScope(tx, g); err != nil {
					return err
				}
				ids = append(ids, g.ID)
			}
		}
	}
	choice, _ := json.Marshal(req.Scope)
	if _, err := tx.Exec(`DELETE FROM decision_scope_receipts WHERE (review_id=? AND revision<?) OR NOT EXISTS(SELECT 1 FROM finding_reviews WHERE id=decision_scope_receipts.review_id)`, req.ID, req.Revision-100); err != nil {
		return err
	}
	raw, _ := json.Marshal(ids)
	if _, err := tx.Exec(`INSERT INTO decision_scope_receipts VALUES(?,?,?,?)`, req.ID, req.Revision, string(choice), string(raw)); err != nil {
		return err
	}
	receipt.ScopeIDs = ids
	return nil
}

func (s *Store) ListDecisionScopes() ([]model.DecisionScope, error) {
	rows, err := s.db.Query(`SELECT record_json FROM decision_scopes ORDER BY rowid DESC LIMIT 10000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.DecisionScope{}
	for rows.Next() {
		var raw string
		var g model.DecisionScope
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ExplainDecisionScope describes the latest permission for the same agent,
// rule and exact resource. Legacy policy semantics remain in their own stores.
func (s *Store) ExplainDecisionScope(q model.DecisionScope) string {
	if q.IdentityBasis == "" {
		return "Live session or executable identity is incomplete; choose once."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	var raw string
	var previous model.DecisionScope
	err := s.db.QueryRowContext(ctx, `SELECT record_json FROM decision_scopes WHERE agent=? AND rule_id=? AND json_extract(record_json,'$.resource_path')=? ORDER BY rowid DESC LIMIT 1`, q.Agent, q.RuleID, q.ResourcePath).Scan(&raw)
	if err == sql.ErrNoRows {
		return "No saved permission covers this request."
	}
	if err != nil || json.Unmarshal([]byte(raw), &previous) != nil {
		return "Saved permission status is unavailable; choose once or retry."
	}
	return previous.MismatchReason(q, time.Now().UTC())
}

func (s *Store) RevokeDecisionScope(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	var g model.DecisionScope
	if err = tx.QueryRow(`SELECT record_json FROM decision_scopes WHERE id=?`, id).Scan(&raw); err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(raw), &g); err != nil {
		return err
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt = time.Now().UTC()
	}
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE decision_scopes SET record_json=? WHERE id=?`, string(b), id); err != nil {
		return err
	}
	return tx.Commit()
}
