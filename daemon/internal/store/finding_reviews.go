package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const maxFindingReviews = 10000

// Promotion preserves source links; colliding contexts stay isolated rather
// than inheriting decisions. Earlier receipts cannot close the new revision.
func rekeyFindingReviewsTx(tx *sql.Tx, oldID, newID string) error {
	rows, err := tx.Query(`SELECT id,state,record_json FROM finding_reviews WHERE session_id=?`, oldID)
	if err != nil {
		return err
	}
	var records []model.ReviewRecord
	for rows.Next() {
		var r model.ReviewRecord
		if r, err = reviewFromRow(rows); err != nil {
			break
		}
		records = append(records, r)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, r := range records {
		r.Context.SessionID = newID
		reliable, err := reliableReviewSession(tx, newID)
		if err != nil {
			return err
		}
		if reliable && r.Context.Rule == "sensitive-read-then-connect" && len(r.Context.Readers) > 0 && len(r.Context.Resources) > 0 && len(r.Context.Destinations) > 0 {
			r.Context.Attribution = "stored-session"
			r.Context.SourceID = ""
		}
		var collision string
		err = tx.QueryRow(`SELECT id FROM finding_reviews WHERE context_key=? AND id!=?`, r.Context.Key(), r.ID).Scan(&collision)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if collision != "" {
			r.Context.Attribution = "promoted-source"
			r.Context.SourceID = r.ID
		}
		r.Revision++
		r.ReviewState = "unreviewed"
		r.Assessment.ReviewState = r.ReviewState
		if err = saveReview(tx, r); err != nil {
			return err
		}
		sources, e := reviewSourcesTx(tx, r.ID)
		if e != nil {
			return e
		}
		for _, v := range sources {
			if _, e = tx.Exec(`UPDATE finding_review_members SET source_key=? WHERE flag_id=?`, model.ReviewEvidenceKey(v.flag, model.AssessFinding(v.flag)), v.flag.ID); e != nil {
				return e
			}
		}
	}
	return nil
}

var (
	ErrReviewConflict = errors.New("review evidence changed")
	ErrReviewCapacity = errors.New("review storage capacity reached")
	ErrReviewMissing  = errors.New("review unavailable")
)

const findingReviewsSchema = `
CREATE TABLE IF NOT EXISTS finding_reviews (
 id TEXT PRIMARY KEY, context_key TEXT UNIQUE NOT NULL, session_id TEXT NOT NULL,
 record_json TEXT NOT NULL, state TEXT NOT NULL, last_seen TEXT NOT NULL, closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_finding_reviews_state ON finding_reviews(state,last_seen,id);
CREATE INDEX IF NOT EXISTS idx_finding_reviews_session ON finding_reviews(session_id);
CREATE TABLE IF NOT EXISTS finding_review_members (
 flag_id TEXT PRIMARY KEY, review_id TEXT NOT NULL, count INTEGER NOT NULL, last_seen TEXT NOT NULL, source_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_review_members_review ON finding_review_members(review_id,last_seen);
CREATE TABLE IF NOT EXISTS finding_review_actions (
 review_id TEXT NOT NULL, revision INTEGER NOT NULL, action TEXT NOT NULL, at TEXT NOT NULL,
 PRIMARY KEY(review_id,revision,action)
);`

// ObserveFindingReview is a best-effort read-model write. Its failure never
// rolls back detector evidence, and is independently visible in write health.
func (s *Store) ObserveFindingReview(f model.Flag, a model.FindingAssessment) (r model.ReviewRecord, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err = s.observeFindingReviewLocked(f, a)
	s.noteWrite("finding reviews", err)
	return
}

func reliableReviewSession(tx *sql.Tx, id string) (bool, error) {
	var confidence, started string
	err := tx.QueryRow(`SELECT COALESCE(confidence,''),COALESCE(root_started_at,'') FROM sessions WHERE id=?`, id).Scan(&confidence, &started)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return id != "" && (confidence == model.ConfHook || confidence == model.ConfTranscript || (confidence == model.ConfProcessTree && started != "")), err
}

// Review identity and workflow state must agree with the indexed row before
// its payload can drive coverage, a decision or a session promotion.
func reviewFromRow(row interface{ Scan(...any) error }) (model.ReviewRecord, error) {
	var id, state, raw string
	if err := row.Scan(&id, &state, &raw); err != nil {
		return model.ReviewRecord{}, err
	}
	var r model.ReviewRecord
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return model.ReviewRecord{}, err
	}
	if id == "" || r.ID != id || r.Revision < 1 {
		return model.ReviewRecord{}, fmt.Errorf("invalid finding review identity or revision")
	}
	switch state {
	case "unreviewed", "reviewed", "closed_reported":
	default:
		return model.ReviewRecord{}, fmt.Errorf("invalid finding review state")
	}
	if r.ReviewState != state {
		return model.ReviewRecord{}, fmt.Errorf("finding review state mismatch")
	}
	r.Assessment.DetectorSeverity = r.Severity
	return r, nil
}

func saveReview(tx *sql.Tx, r model.ReviewRecord) error {
	// Link lists and availability are derived from current source retention.
	r.SourceIDs = nil
	r.IncidentIDs = nil
	r.EvidenceAvailable = false
	r.EvidenceFlagAvailable = false
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var closed any
	if r.ReviewState == "closed_reported" && r.Decision != nil {
		closed = r.Decision.At.UTC().Format(time.RFC3339Nano)
	}
	_, err = tx.Exec(`INSERT INTO finding_reviews(id,context_key,session_id,record_json,state,last_seen,closed_at) VALUES (?,?,?,?,?,?,?)
 ON CONFLICT(id) DO UPDATE SET context_key=excluded.context_key,session_id=excluded.session_id,record_json=excluded.record_json,state=excluded.state,last_seen=excluded.last_seen,closed_at=excluded.closed_at`, r.ID, r.Context.Key(), r.Context.SessionID, string(b), r.ReviewState, r.LastSeen.UTC().Format(time.RFC3339Nano), closed)
	return err
}

func assessmentRank(a model.FindingAssessment) int {
	switch a.Risk {
	case "critical":
		return 4
	case "high":
		return 3
	case "review":
		return 2
	case "informational":
		return 1
	}
	return a.DetectorSeverity
}

// mergeReviewAssessment retains the strongest observed facts, including late
// arrivals. Advice, timestamps, count and workflow are not semantic evidence.
func mergeReviewAssessment(old, next model.FindingAssessment) (model.FindingAssessment, bool) {
	basis := append(slices.Clone(old.EvidenceBasis), next.EvidenceBasis...)
	slices.Sort(basis)
	basis = slices.Compact(basis)
	chosen := old
	if assessmentRank(next) > assessmentRank(old) || (assessmentRank(next) == assessmentRank(old) && old.Risk == "unknown" && next.Risk != "unknown") {
		chosen = next
	}
	if next.Control != "unknown" && next.Control != "" {
		chosen.Control = next.Control
	}
	changed := !slices.Equal(basis, old.EvidenceBasis) || chosen.Risk != old.Risk || chosen.ResidualRisk != old.ResidualRisk || chosen.Control != old.Control || next.DetectorSeverity > old.DetectorSeverity
	chosen.EvidenceBasis = basis
	chosen.Advice = nil
	chosen.DetectorSeverity = max(old.DetectorSeverity, next.DetectorSeverity)
	return chosen, changed
}

func (s *Store) observeFindingReviewLocked(f model.Flag, a model.FindingAssessment) (model.ReviewRecord, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.ReviewRecord{}, err
	}
	defer tx.Rollback()
	r, err := observeReviewTx(tx, f, a)
	if err == nil {
		err = tx.Commit()
	}
	if err == nil {
		s.reviewWrites++
		if s.reviewWrites%100 == 0 {
			_, err = s.db.Exec(`DELETE FROM finding_review_members WHERE flag_id NOT IN (SELECT id FROM flags)`)
		}
	}
	return r, err
}

func observeReviewTx(tx *sql.Tx, f model.Flag, a model.FindingAssessment) (r model.ReviewRecord, err error) {
	var exists int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM flags WHERE id=?`, f.ID).Scan(&exists); err != nil {
		return
	}
	if exists != 1 {
		return r, ErrReviewMissing
	}
	reliable, err := reliableReviewSession(tx, f.SessionID)
	if err != nil {
		return r, err
	}
	c := model.ContextForReview(f, reliable)
	id := c.Key()
	var priorID string
	var priorCount int
	err = tx.QueryRow(`SELECT review_id,count FROM finding_review_members WHERE flag_id=?`, f.ID).Scan(&priorID, &priorCount)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	// An existing source must never be silently moved into a different
	// decision context by an update. Identity promotion has its own transaction.
	r, err = reviewFromRow(tx.QueryRow(`SELECT id,state,record_json FROM finding_reviews WHERE context_key=?`, id))
	if err == nil {
		id = r.ID
	}
	if priorID != "" && priorID != id {
		prior, e := reviewFromRow(tx.QueryRow(`SELECT id,state,record_json FROM finding_reviews WHERE id=?`, priorID))
		if e != nil {
			return r, e
		}
		expected := prior.Context
		expected.Attribution = c.Attribution
		expected.SourceID = c.SourceID
		if prior.Context.Attribution != "promoted-source" || expected.Key() != c.Key() {
			return r, ErrReviewConflict
		}
		r = prior
		id = priorID
		err = nil
	}
	fresh := errors.Is(err, sql.ErrNoRows)
	if err != nil && !fresh {
		return r, err
	}
	seen := f.TS
	if f.LastSeen != nil && f.LastSeen.After(seen) {
		seen = *f.LastSeen
	}
	if fresh {
		if _, err = tx.Exec(`DELETE FROM finding_review_actions WHERE review_id IN (SELECT id FROM finding_reviews WHERE state='closed_reported' AND closed_at<?)`, time.Now().Add(-30*24*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
			return
		}
		if _, err = tx.Exec(`DELETE FROM finding_review_members WHERE review_id IN (SELECT id FROM finding_reviews WHERE state='closed_reported' AND closed_at<?)`, time.Now().Add(-30*24*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
			return
		}
		if _, err = tx.Exec(`DELETE FROM finding_reviews WHERE state='closed_reported' AND closed_at<?`, time.Now().Add(-30*24*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
			return
		}
		var total int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM finding_reviews`).Scan(&total); err != nil {
			return
		}
		if total >= maxFindingReviews {
			return r, ErrReviewCapacity
		}
		a.EvidenceBasis = slices.Clone(a.EvidenceBasis)
		slices.Sort(a.EvidenceBasis)
		a.Advice = nil
		r = model.ReviewRecord{ID: id, Revision: 1, Context: c, Agent: f.Agent, PID: f.PID, Severity: f.Severity, Assessment: a, ReviewState: "unreviewed", FirstSeen: f.TS, LastSeen: seen, LatestFlagID: f.ID, EvidenceFlagID: f.ID}
		if f.Acknowledged {
			r.ReviewState = "reviewed"
			r.ReviewedRevision = 1
		}
	} else {
		if !f.Acknowledged && r.Decision == nil && r.ReviewState == "reviewed" {
			r.ReviewState = "unreviewed"
		}
		if assessmentRank(a) > assessmentRank(r.Assessment) || (assessmentRank(a) == assessmentRank(r.Assessment) && r.Assessment.Risk == "unknown" && a.Risk != "unknown") {
			r.EvidenceFlagID = f.ID
		}
		merged, changed := mergeReviewAssessment(r.Assessment, a)
		r.Assessment = merged
		r.Severity = max(r.Severity, f.Severity)
		if changed {
			r.Revision++
			r.ReviewState = "unreviewed"
		}
		if f.TS.Before(r.FirstSeen) {
			r.FirstSeen = f.TS
		}
		if seen.After(r.LastSeen) {
			r.LastSeen = seen
			r.LatestFlagID = f.ID
		}
	}
	if _, err = tx.Exec(`INSERT INTO finding_review_members(flag_id,review_id,count,last_seen,source_key) VALUES (?,?,?,?,?)
 ON CONFLICT(flag_id) DO UPDATE SET count=MAX(count,excluded.count),last_seen=CASE WHEN last_seen<excluded.last_seen THEN excluded.last_seen ELSE last_seen END,source_key=excluded.source_key`, f.ID, id, 1+max(0, f.Repeats), seen.UTC().Format(time.RFC3339Nano), model.ReviewEvidenceKey(f, a)); err != nil {
		return
	}
	r.Count += max(0, 1+max(0, f.Repeats)-priorCount)
	r.Assessment.ReviewState = r.ReviewState
	if r.ReviewState != "unreviewed" {
		// Identical new observations inherit the review, not a permission.
		_, err = tx.Exec(`UPDATE flags SET acknowledged=COALESCE(NULLIF(acknowledged,''),?) WHERE id IN (SELECT flag_id FROM finding_review_members WHERE review_id=?)`, time.Now().UTC().Format(time.RFC3339Nano), id)
		if err != nil {
			return
		}
	}
	if err = saveReview(tx, r); err != nil {
		return
	}
	return r, nil
}

func (s *Store) GetFindingReview(id string) (r model.ReviewRecord, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.noteRead("finding reviews", err) }()
	r, err = reviewFromRow(s.db.QueryRow(`SELECT id,state,record_json FROM finding_reviews WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err == nil {
		err = s.reviewLinksLocked(&r)
	}
	return r, err == nil, err
}

func (s *Store) reviewLinksLocked(r *model.ReviewRecord) error {
	rows, err := s.db.Query(`SELECT m.flag_id FROM finding_review_members m JOIN flags f ON f.id=m.flag_id WHERE m.review_id=? ORDER BY m.last_seen DESC,m.flag_id LIMIT 100`, r.ID)
	if err != nil {
		return err
	}
	r.SourceIDs = []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		r.SourceIDs = append(r.SourceIDs, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	r.EvidenceAvailable = len(r.SourceIDs) > 0
	var available int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM flags WHERE id=?`, r.EvidenceFlagID).Scan(&available); err != nil {
		return err
	}
	r.EvidenceFlagAvailable = available == 1
	r.AvailableScopes = nil
	if r.EvidenceAvailable && r.ReviewState != "closed_reported" && (r.Decision == nil || r.Decision.Action != "expect" || r.Decision.Revision != r.Revision) {
		r.AvailableScopes = []model.ScopeChoice{{Kind: "once"}}
		complete := true
		for _, id := range r.SourceIDs {
			f, ok, readErr := s.getFlagResultLocked(id)
			if readErr != nil {
				return readErr
			}
			coordinates, e := model.ReadConnectScopes(f)
			if !ok || e != nil {
				complete = false
				break
			}
			for _, g := range coordinates {
				model.ScopeChoice{Kind: "session"}.Apply(&g, time.Now().UTC())
				if g.Validate() != nil || !scopeSession(s.db, g) {
					complete = false
					break
				}
			}
			if !complete {
				break
			}
		}
		if complete {
			r.AvailableScopes = append(r.AvailableScopes, model.ScopeChoice{Kind: "session"}, model.ScopeChoice{Kind: "exact", Expiry: "24h"}, model.ScopeChoice{Kind: "exact", Expiry: "7d"})
		}
	}
	rows, err = s.db.Query(`SELECT id FROM incidents WHERE flag_id IN (SELECT flag_id FROM finding_review_members WHERE review_id=?)
 UNION SELECT id FROM incidents WHERE COALESCE(rule,'')=? AND COALESCE(session_id,'')=? AND EXISTS(SELECT 1 FROM json_each(flag_ids) WHERE value IN (SELECT flag_id FROM finding_review_members WHERE review_id=?)) ORDER BY id LIMIT 100`, r.ID, r.Context.Rule, r.Context.SessionID, r.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	r.IncidentIDs = []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return err
		}
		r.IncidentIDs = append(r.IncidentIDs, id)
	}
	return rows.Err()
}

type ReviewPage struct {
	Reviews  []model.ReviewRecord `json:"reviews"`
	Next     string               `json:"next,omitempty"`
	Degraded bool                 `json:"degraded"`
}

func (s *Store) ListFindingReviews(after string, limit int) (page ReviewPage, err error) {
	return s.ListFindingReviewsState(after, limit, "")
}

func (s *Store) ListFindingReviewsState(after string, limit int, state string) (page ReviewPage, err error) {
	return s.listFindingReviews(after, limit, state, "")
}

// ListSessionFindingReviews reads the newest retained reviews for one exact
// session, including reported closure. It does not change review or permission.
func (s *Store) ListSessionFindingReviews(sessionID string) (ReviewPage, error) {
	if sessionID == "" {
		return ReviewPage{}, fmt.Errorf("session identity required")
	}
	return s.listFindingReviews("", 100, "", sessionID)
}

func (s *Store) listFindingReviews(after string, limit int, state, sessionID string) (page ReviewPage, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		s.noteRead("finding reviews", err)
		if err != nil {
			page = ReviewPage{Reviews: []model.ReviewRecord{}, Degraded: true}
		}
	}()
	limit = min(max(limit, 1), 100)
	page.Reviews = []model.ReviewRecord{}
	query := `SELECT id,state,record_json FROM finding_reviews WHERE id>? AND (?='' OR state=?) ORDER BY id LIMIT ?`
	args := []any{after, state, state, limit + 1}
	if sessionID != "" {
		query = `SELECT id,state,record_json FROM finding_reviews WHERE session_id=? ORDER BY last_seen DESC,id DESC LIMIT ?`
		args = []any{sessionID, limit + 1}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		page.Degraded = true
		return
	}
	for rows.Next() {
		var r model.ReviewRecord
		if r, err = reviewFromRow(rows); err != nil {
			break
		}
		page.Reviews = append(page.Reviews, r)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		page.Degraded = true
		return
	}
	if len(page.Reviews) > limit {
		page.Reviews = page.Reviews[:limit]
		page.Next = page.Reviews[limit-1].ID
	}
	for i := range page.Reviews {
		if err = s.reviewLinksLocked(&page.Reviews[i]); err != nil {
			page.Degraded = true
			return
		}
	}
	h := s.WriteHealth()
	page.Degraded = slices.Contains(h.Active, "finding reviews")
	return
}

// FindingReviewID resolves coverage without returning bounded history links.
func (s *Store) FindingReviewID(flagID string) (id string, readErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.noteRead("finding reviews", readErr) }()
	var key string
	err := s.db.QueryRow(`SELECT review_id,source_key FROM finding_review_members WHERE flag_id=?`, flagID).Scan(&id, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err == nil {
		f, found, flagErr := s.getFlagResultLocked(flagID)
		if flagErr != nil {
			return "", flagErr
		}
		if !found || model.ReviewEvidenceKey(f, model.AssessFinding(f)) != key {
			return "", nil
		}
	}
	return id, err
}

func (s *Store) DecideFindingReview(req model.ReviewDecisionRequest) (receipt model.ReviewDecisionReceipt, err error) {
	if req.Revision < 1 || (req.Action != "acknowledge" && req.Action != "close_reported" && req.Action != "expect") ||
		(req.Action == "expect" && (req.Scope == nil || req.Scope.Validate() != nil)) || (req.Action != "expect" && req.Scope != nil) {
		return receipt, fmt.Errorf("invalid review decision")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil && !errors.Is(err, ErrReviewConflict) && !errors.Is(err, ErrReviewMissing) {
			s.noteWrite("finding reviews", err)
		}
	}()
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	r, err := reviewFromRow(tx.QueryRow(`SELECT id,state,record_json FROM finding_reviews WHERE id=?`, req.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, ErrReviewMissing
	}
	if err != nil {
		return
	}
	if r.Revision != req.Revision {
		return receipt, ErrReviewConflict
	}
	sources, e := reviewSourcesTx(tx, r.ID)
	if e != nil {
		return receipt, e
	}
	for _, v := range sources {
		if model.ReviewEvidenceKey(v.flag, model.AssessFinding(v.flag)) != v.key {
			return receipt, ErrReviewConflict
		}
	}
	var n int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM flags f JOIN finding_review_members m ON m.flag_id=f.id WHERE m.review_id=?`, req.ID).Scan(&n); err != nil {
		return
	}
	if n == 0 {
		return receipt, ErrReviewMissing
	}
	var at string
	err = tx.QueryRow(`SELECT at FROM finding_review_actions WHERE review_id=? AND revision=? AND action=?`, req.ID, req.Revision, req.Action).Scan(&at)
	if err == nil {
		receipt = model.ReviewDecisionReceipt{ID: req.ID, Revision: req.Revision, Action: req.Action}
		receipt.At, _ = time.Parse(time.RFC3339Nano, at)
		if req.Action == "expect" {
			var choice, ids string
			if err = tx.QueryRow(`SELECT choice_json,ids_json FROM decision_scope_receipts WHERE review_id=? AND revision=?`, req.ID, req.Revision).Scan(&choice, &ids); err != nil {
				return receipt, err
			}
			b, _ := json.Marshal(req.Scope)
			if choice != string(b) {
				return receipt, ErrReviewConflict
			}
			if err = json.Unmarshal([]byte(ids), &receipt.ScopeIDs); err != nil {
				return receipt, err
			}
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return
	}
	if r.ReviewState == "closed_reported" {
		return receipt, ErrReviewConflict
	}
	receipt = model.ReviewDecisionReceipt{ID: req.ID, Revision: req.Revision, Action: req.Action, At: time.Now().UTC()}
	if req.Action == "expect" {
		if err = createReviewScopesTx(tx, req, sources, &receipt); err != nil {
			return receipt, err
		}
	}
	if _, err = tx.Exec(`UPDATE flags SET acknowledged=COALESCE(NULLIF(acknowledged,''),?) WHERE id IN (SELECT flag_id FROM finding_review_members WHERE review_id=?)`, receipt.At.Format(time.RFC3339Nano), req.ID); err != nil {
		return
	}
	r.ReviewState = "reviewed"
	if req.Action == "close_reported" {
		r.ReviewState = "closed_reported"
	}
	r.ReviewedRevision = r.Revision
	r.Decision = &receipt
	r.Assessment.ReviewState = r.ReviewState
	if err = saveReview(tx, r); err != nil {
		return
	}
	if _, err = tx.Exec(`INSERT INTO finding_review_actions VALUES (?,?,?,?)`, req.ID, req.Revision, req.Action, receipt.At.Format(time.RFC3339Nano)); err != nil {
		return
	}
	// Bound receipts per review; the latest receipt remains in record_json.
	if _, err = tx.Exec(`DELETE FROM finding_review_actions WHERE review_id=? AND revision<?`, req.ID, r.Revision-100); err != nil {
		return
	}
	err = tx.Commit()
	if err == nil {
		s.noteWrite("finding reviews", nil)
	}
	return
}

// backfillFindingReviews is restart-safe and bounded by the existing flag cap.
// Reads close before starting writes (the store owns one SQLite connection).
func (s *Store) backfillFindingReviews() error {
	var cursor int64
	var allIDs []string
	for {
		rows, err := s.db.Query(`SELECT rowid,id FROM flags WHERE rule='sensitive-read-then-connect' AND rowid>? ORDER BY rowid LIMIT 100`, cursor)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&cursor, &id); err != nil {
				break
			}
			ids = append(ids, id)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			s.mu.Lock()
			s.syncLegacyReviewsLocked(allIDs)
			s.mu.Unlock()
			return nil
		}
		allIDs = append(allIDs, ids...)
		for _, id := range ids {
			f, ok := s.GetFlag(id)
			if !ok {
				continue
			}
			if _, err = s.ObserveFindingReview(f, model.AssessFinding(f)); err != nil {
				return err
			}
		}
	}
}

// Legacy clients still acknowledge source flags. Reflect a legacy receipt
// only when every current member is acknowledged and its projection matches.
func (s *Store) syncLegacyReviewsLocked(ids []string) {
	for _, id := range ids {
		var reviewID string
		if err := s.db.QueryRow(`SELECT review_id FROM finding_review_members WHERE flag_id=?`, id).Scan(&reviewID); err != nil {
			continue
		}
		r, err := reviewFromRow(s.db.QueryRow(`SELECT id,state,record_json FROM finding_reviews WHERE id=?`, reviewID))
		if err != nil || r.Decision != nil {
			continue
		}
		rows, err := s.db.Query(`SELECT m.flag_id,m.source_key,COALESCE(f.acknowledged,'') FROM finding_review_members m JOIN flags f ON f.id=m.flag_id WHERE m.review_id=?`, reviewID)
		if err != nil {
			s.noteWrite("finding reviews", err)
			continue
		}
		type source struct{ id, key, at string }
		var sources []source
		for rows.Next() {
			var v source
			if err = rows.Scan(&v.id, &v.key, &v.at); err != nil {
				break
			}
			sources = append(sources, v)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			s.noteWrite("finding reviews", err)
			continue
		}
		all := len(sources) > 0
		var at time.Time
		var closedAt time.Time
		closed, undatedClosure := false, false
		for _, v := range sources {
			f, ok := s.getFlagLocked(v.id)
			stamp, e := time.Parse(time.RFC3339Nano, v.at)
			if !ok || model.ReviewEvidenceKey(f, model.AssessFinding(f)) != v.key {
				all = false
				break
			}
			var resolved sql.NullString
			legacyErr := s.db.QueryRow(`SELECT resolved_at FROM incidents WHERE status='resolved' AND (flag_id=? OR (COALESCE(rule,'')=? AND COALESCE(session_id,'')=? AND EXISTS(SELECT 1 FROM json_each(flag_ids) WHERE value=?))) ORDER BY created_at DESC LIMIT 1`, v.id, r.Context.Rule, r.Context.SessionID, v.id).Scan(&resolved)
			if legacyErr == nil {
				closed = true
				resolvedAt, parseErr := time.Parse(time.RFC3339Nano, resolved.String)
				if parseErr != nil {
					undatedClosure = true
				} else if resolvedAt.After(closedAt) {
					closedAt = resolvedAt
				}
			} else if !errors.Is(legacyErr, sql.ErrNoRows) {
				s.noteWrite("finding reviews", legacyErr)
				all = false
				break
			} else if e != nil {
				all = false
				break
			}
			if stamp.After(at) {
				at = stamp
			}
		}
		if !all {
			continue
		}
		r.ReviewState = "reviewed"
		r.ReviewedRevision = r.Revision
		r.Assessment.ReviewState = r.ReviewState
		r.Decision = &model.ReviewDecisionReceipt{ID: r.ID, Revision: r.Revision, Action: "acknowledge", At: at, Source: "legacy-source-state"}
		if closed {
			r.ReviewState = "closed_reported"
			r.Assessment.ReviewState = r.ReviewState
			if undatedClosure {
				r.Decision = nil
			} else {
				r.Decision = &model.ReviewDecisionReceipt{ID: r.ID, Revision: r.Revision, Action: "close_reported", At: closedAt, Source: "legacy-incident-status"}
			}
		}
		tx, e := s.db.Begin()
		if e != nil {
			s.noteWrite("finding reviews", e)
			continue
		}
		e = saveReview(tx, r)
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
		s.noteWrite("finding reviews", e)
	}
}
