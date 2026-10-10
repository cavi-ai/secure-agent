package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// PutIncident creates a report and rejects existing identities without changing
// their evidence or operator bookkeeping. Retention pruning remains best-effort
// and does not invalidate a successful insertion.
func (s *Store) PutIncident(inc model.IncidentReport) (writeErr error) {
	defer func() {
		s.noteWrite("incidents", writeErr)
		if writeErr != nil {
			log.Printf("store: failed to persist incident %s: %v", inc.ID, writeErr)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()

	inc.Remediation = nil
	if inc.AggregateCount == 0 {
		inc.AggregateCount = 1
	}
	data, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("marshal incident: %w", err)
	}

	tsStr := inc.Timestamp.UTC().Format(time.RFC3339Nano)
	flagIDs, _ := json.Marshal([]string{inc.FlagID})
	result, err := s.db.Exec(
		`INSERT INTO incidents (id, flag_id, pid, risk, report_json, created_at, rule, session_id, subject, aggregate_count, last_flag_at, flag_ids, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`,
		inc.ID, inc.FlagID, inc.PID, string(inc.Risk), string(data), tsStr,
		inc.Rule, inc.SessionID, inc.Subject, inc.AggregateCount, tsStr, string(flagIDs),
	)
	if err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("incident rows affected: %w", err)
	}
	if inserted != 1 {
		return fmt.Errorf("incident insert affected %d rows", inserted)
	}

	// Retention: a flag storm inserts a full report_json per incident; cap the
	// table so the always-on daemon's DB stays bounded (events are already capped).
	// Order by the normalized instant, not raw text: local-offset stamps sort
	// wrong lexicographically across a DST change.
	_, _ = s.db.Exec(trimIncidentsSQL, maxIncidents)
	return nil
}

func (s *Store) GetIncident(id string) (report *model.IncidentReport, readErr error) {
	defer func() {
		if readErr == sql.ErrNoRows {
			s.noteRead("incidents", nil)
		} else {
			s.noteRead("incidents", readErr)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()

	storedID, reportJSON, err := s.resolveIncidentRowLocked(s.db, id)
	if err != nil {
		return nil, err
	}

	inc, err := decodeIncidentReport(storedID, reportJSON)
	if err != nil {
		return nil, err
	}
	if err := s.attachIncidentRemediationLocked(inc); err != nil {
		return nil, err
	}
	if v, ok := s.advisorVerdictLocked(inc.ID, "incident"); ok {
		inc.AdvisorNarrative = v.Rationale
	}
	return inc, nil
}

func decodeIncidentReport(id, reportJSON string) (*model.IncidentReport, error) {
	var inc *model.IncidentReport
	if err := json.Unmarshal([]byte(reportJSON), &inc); err != nil {
		return nil, err
	}
	if inc == nil || inc.ID == "" || inc.ID != id {
		return nil, fmt.Errorf("invalid incident report identity")
	}
	return inc, nil
}

// IncidentIDForFlag returns the incident a flag opened or was aggregated
// into (newest first).
func (s *Store) IncidentIDForFlag(flagID string) (string, bool) {
	id, found, _ := s.IncidentIDForFlagResult(flagID)
	return id, found
}

// FindOpenIncident returns the open (unresolved) incident matching the
// aggregation key — one incident per rule+session+subject; repeat flags
// become its evidence instead of minting duplicate reports.
func (s *Store) FindOpenIncident(rule, sessionID, subject string) (string, bool) {
	id, found, _ := s.FindOpenIncidentResult(rule, sessionID, subject)
	return id, found
}

// FindOpenIncidentResult distinguishes a missing aggregation target from an
// unavailable or invalid stored identity. Callers creating reports must use it.
func (s *Store) FindOpenIncidentResult(rule, sessionID, subject string) (id string, found bool, readErr error) {
	defer func() { s.noteRead("incident lookup", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	return findOpenIncident(s.db, rule, sessionID, subject)
}

func findOpenIncident(q incidentRowQueryer, rule, sessionID, subject string) (id string, found bool, readErr error) {
	err := q.QueryRow(findOpenIncidentSQL, rule, sessionID, subject).Scan(&id)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if id == "" {
		return "", false, fmt.Errorf("invalid open incident identity")
	}
	return id, true, nil
}

// AbsorbOpenIncident selects and aggregates in one transaction. Persisted is
// true only when the returned evidence is durable (including an unchanged
// replay). False with nil error means no open target; failures return an error
// so callers cannot mistake them for permission to create another report.
func (s *Store) AbsorbOpenIncident(rule, sessionID, subject, flagID string, ts time.Time) (model.IncidentReport, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		s.noteRead("incident lookup", err)
		return model.IncidentReport{}, false, err
	}
	defer tx.Rollback()
	id, found, err := findOpenIncident(tx, rule, sessionID, subject)
	s.noteRead("incident lookup", err)
	if err != nil || !found {
		return model.IncidentReport{}, false, err
	}
	report, err := s.aggregateIncidentLocked(tx, id, flagID, ts)
	return report, err == nil, err
}

// AggregateIntoIncident uses the same exact-ID-first, newest-flag-alias
// precedence as detail, workflow, and remediation. False means the report
// could not be returned as durable evidence.
func (s *Store) AggregateIntoIncident(id, flagID string, ts time.Time) (model.IncidentReport, bool) {
	if id == "" || flagID == "" {
		return model.IncidentReport{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		s.noteWrite("incident aggregation", err)
		return model.IncidentReport{}, false
	}
	defer tx.Rollback()
	storedID, err := resolveIncidentID(tx, id)
	if err != nil {
		if err != sql.ErrNoRows {
			s.noteWrite("incident aggregation", err)
		}
		return model.IncidentReport{}, false
	}
	report, err := s.aggregateIncidentLocked(tx, storedID, flagID, ts)
	return report, err == nil
}

// aggregateIncidentLocked owns evidence decoding, outcome accounting,
// remediation projection, and commit. It receives a canonical identity selected
// in the same transaction. No partial write or unreadable report is published.
func (s *Store) aggregateIncidentLocked(tx *sql.Tx, id, flagID string, ts time.Time) (model.IncidentReport, error) {
	fail := func(err error) (model.IncidentReport, error) {
		s.noteWrite("incident aggregation", err)
		return model.IncidentReport{}, err
	}
	if flagID == "" {
		return fail(fmt.Errorf("empty incident flag identity"))
	}
	var reportJSON, flagIDsRaw string
	var count int
	err := tx.QueryRow(`SELECT report_json, COALESCE(flag_ids,'[]'), COALESCE(aggregate_count,1) FROM incidents WHERE id = ?`, id).
		Scan(&reportJSON, &flagIDsRaw, &count)
	if err != nil {
		return fail(err)
	}
	var storedFlagIDs []*string
	if err := json.Unmarshal([]byte(flagIDsRaw), &storedFlagIDs); err != nil {
		return fail(err)
	}
	if storedFlagIDs == nil {
		return fail(fmt.Errorf("null incident flag evidence"))
	}
	flagIDs := make([]string, len(storedFlagIDs))
	for i, storedID := range storedFlagIDs {
		if storedID == nil {
			return fail(fmt.Errorf("null incident flag identity"))
		}
		flagIDs[i] = *storedID
	}
	inc, err := decodeIncidentReport(id, reportJSON)
	if err != nil {
		return fail(err)
	}
	if inc.FlagID != "" && !slices.Contains(flagIDs, inc.FlagID) {
		flagIDs = append(flagIDs, inc.FlagID)
	}
	replay := slices.Contains(flagIDs, flagID)
	if !replay {
		if inc.Rule == "proxy-secret-leak" {
			if inc.PayloadOutcomes == nil {
				// Historic reports do not establish their control outcomes.
				inc.PayloadOutcomes = &model.PayloadOutcomeSummary{Unknown: count}
			}
			var source model.Flag
			var evidence string
			err := tx.QueryRow(`SELECT rule, evidence FROM flags WHERE id = ?`, flagID).Scan(&source.Rule, &evidence)
			if err != nil && err != sql.ErrNoRows {
				return fail(err)
			}
			if err == nil {
				if err := json.Unmarshal([]byte(evidence), &source.Evidence); err != nil {
					return fail(err)
				}
			}
			outcome := model.PayloadOutcomeForFinding(source)
			if outcome == nil {
				outcome = &model.PayloadOutcomeSummary{Unknown: 1}
			}
			inc.PayloadOutcomes.Blocked += outcome.Blocked
			inc.PayloadOutcomes.ObservedOnly += outcome.ObservedOnly
			inc.PayloadOutcomes.Unknown += outcome.Unknown
		}
		flagIDs = append(flagIDs, flagID)
		count++
		inc.AggregateCount = count
		t := ts.UTC()
		if inc.Timestamp.After(t) {
			t = inc.Timestamp.UTC()
		}
		if inc.LastFlagAt != nil && inc.LastFlagAt.After(t) {
			t = inc.LastFlagAt.UTC()
		}
		inc.LastFlagAt = &t
		data, err := json.Marshal(inc)
		if err != nil {
			return fail(err)
		}
		idsJSON, err := json.Marshal(flagIDs)
		if err != nil {
			return fail(err)
		}
		tsStr := t.Format(time.RFC3339Nano)
		reportJSON = string(data)
		result, err := tx.Exec(`UPDATE incidents SET aggregate_count = ?, last_flag_at = ?, flag_ids = ?, report_json = ? WHERE id = ?`,
			count, tsStr, string(idsJSON), reportJSON, id)
		if err != nil {
			return fail(err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return fail(err)
		}
		if updated != 1 {
			return model.IncidentReport{}, fmt.Errorf("incident aggregation affected %d rows", updated)
		}
		// Triggers can change or remove the row after UPDATE. Verify every
		// written field before committing or returning a successful delta.
		var savedReport, savedIDs, savedTime string
		var savedCount int
		if err := tx.QueryRow(`SELECT report_json, flag_ids, aggregate_count, last_flag_at FROM incidents WHERE id=?`, id).
			Scan(&savedReport, &savedIDs, &savedCount, &savedTime); err != nil {
			return fail(err)
		}
		if savedReport != reportJSON || savedIDs != string(idsJSON) || savedCount != count || savedTime != tsStr {
			return fail(fmt.Errorf("incident aggregation result changed during write"))
		}
	}
	if err := attachIncidentRemediation(tx, inc); err != nil {
		s.noteRead("incidents", err)
		return model.IncidentReport{}, err
	}
	s.noteRead("incidents", nil)
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	if !replay {
		s.noteWrite("incident aggregation", nil)
	}
	return *inc, nil
}

func (s *Store) RecentIncidents(limit int) []model.IncidentReport {
	incidents, _ := s.RecentIncidentsResult(limit)
	return incidents
}

// RecentIncidentsResult returns no partial history after query, scan, report
// decode or cursor failure. Resolved reports remain outside the active set.
func (s *Store) RecentIncidentsResult(limit int) (out []model.IncidentReport, readErr error) {
	defer func() { s.noteRead("incidents", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Resolved incidents stay in the audit trail but leave the active set:
	// the operator dismissed them, so they must not keep rendering as
	// critical rows in the popover.
	rows, err := s.db.Query(recentIncidentsQuery, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	list, err := scanIncidentsResult(rows)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if err := s.attachIncidentRemediationLocked(&list[i]); err != nil {
			return nil, err
		}
	}
	s.attachNarrativesLocked(list)
	return list, nil
}

// Include NULL status so an unreadable workflow cannot silently hide a report.
var recentIncidentsQuery = `SELECT id, report_json FROM incidents WHERE (status IS NULL OR status != 'resolved') ORDER BY ` + timestampOrderExpr("created_at") + ` DESC, id DESC LIMIT ?`

func scanIncidentsResult(rows *sql.Rows) ([]model.IncidentReport, error) {
	defer rows.Close()

	list := []model.IncidentReport{}
	for rows.Next() {
		var id, reportJSON string
		if err := rows.Scan(&id, &reportJSON); err != nil {
			return nil, err
		}
		inc, err := decodeIncidentReport(id, reportJSON)
		if err != nil {
			return nil, err
		}
		list = append(list, *inc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// IncidentIDForFlagResult distinguishes absent reports from unavailable or
// invalid targets using the same identity decoder as incident detail.
func (s *Store) IncidentIDForFlagResult(flagID string) (id string, found bool, readErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.noteRead("incident links", readErr) }()
	return s.incidentIDForFlagLocked(flagID)
}

// IncidentIDsForFlags preserves valid sibling links and records one health
// result for the whole enrichment batch. Empty values mark missing or failed
// lookups so a consumer does not repeat them within the same calculation.
func (s *Store) IncidentIDsForFlags(flagIDs []string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	links := make(map[string]string, len(flagIDs))
	var readErr error
	for _, flagID := range flagIDs {
		if _, seen := links[flagID]; seen {
			continue
		}
		links[flagID] = ""
		id, found, err := s.incidentIDForFlagLocked(flagID)
		if readErr == nil {
			readErr = err
		}
		if found {
			links[flagID] = id
		}
	}
	s.noteRead("incident links", readErr)
	return links, readErr
}

// incidentRowQueryer is the subset of *sql.DB and *sql.Tx that can resolve one
// incident identity. Callers hold Store.mu.
type incidentRowQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

// resolveIncidentRowLocked selects the exact incident id first. An alias cannot
// shadow that row. Otherwise it selects the newest incident whose opening
// flag_id or aggregated flag_ids contains the key.
func (s *Store) resolveIncidentRowLocked(q incidentRowQueryer, key string) (id, reportJSON string, err error) {
	id, err = resolveIncidentID(q, key)
	if err != nil {
		return id, reportJSON, err
	}
	err = q.QueryRow(`SELECT report_json FROM incidents WHERE id = ?`, id).Scan(&reportJSON)
	return id, reportJSON, err
}

// resolveIncidentID follows incident detail identity precedence: an
// exact report ID wins; otherwise the newest report linked to the flag wins.
// Updates use their transaction here so selection and mutation stay together.
func resolveIncidentID(q incidentRowQueryer, id string) (string, error) {
	var storedID string
	err := q.QueryRow(`SELECT id FROM incidents WHERE id = ?`, id).Scan(&storedID)
	if err == sql.ErrNoRows {
		err = q.QueryRow(`SELECT id FROM incidents
			WHERE flag_id = ? OR EXISTS (SELECT 1 FROM json_each(COALESCE(flag_ids,'[]')) WHERE value = ?)
			ORDER BY `+timestampOrderExpr("created_at")+` DESC, id DESC LIMIT 1`, id, id).Scan(&storedID)
	}
	return storedID, err
}

func (s *Store) incidentIDForFlagLocked(flagID string) (string, bool, error) {
	if flagID == "" {
		return "", false, nil
	}
	id, raw, err := s.resolveIncidentRowLocked(s.db, flagID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if _, err := decodeIncidentReport(id, raw); err != nil {
		return "", false, err
	}
	return id, true, nil
}

// IncidentWorkflow is the mutable state layered on top of a stored report.
// The report itself is immutable evidence; ack/resolve is operator bookkeeping.
type IncidentWorkflow struct {
	Status         string `json:"status"` // open | acknowledged | resolved
	AcknowledgedAt string `json:"acknowledged_at,omitempty"`
	ResolvedAt     string `json:"resolved_at,omitempty"`
	ResolutionNote string `json:"resolution_note,omitempty"`
}

// SetIncidentStatus transitions an incident's workflow state. Transitions are
// forward-only: open → acknowledged → resolved. Re-resolving is allowed (note
// is replaced); acknowledged_at is stamped only the first time.
func (s *Store) SetIncidentStatus(id, status, note string) (bool, error) {
	_, updated, err := s.SetIncidentStatusResult(id, status, note)
	return updated, err
}

// ErrInvalidIncidentStatus distinguishes invalid input from storage failure.
var ErrInvalidIncidentStatus = errors.New("invalid incident status")

// SetIncidentStatusResult resolves the same incident identity as lookup inside
// the update transaction, then returns the workflow read in that transaction.
// An unreadable result or failed commit leaves no successful update. Zero
// matching rows are not an error.
func (s *Store) SetIncidentStatusResult(id, status, note string) (workflow IncidentWorkflow, updated bool, writeErr error) {
	var query string
	var args []any
	switch status {
	case "acknowledged":
		query = `UPDATE incidents SET status='acknowledged',
			acknowledged_at=COALESCE(acknowledged_at, ?)
			WHERE id = ?`
		args = []any{time.Now().UTC().Format(time.RFC3339Nano)}
	case "resolved":
		query = `UPDATE incidents SET status='resolved', resolved_at=?, resolution_note=?
			WHERE id = ?`
		args = []any{time.Now().UTC().Format(time.RFC3339Nano), note}
	case "open":
		query = `UPDATE incidents SET status='open', acknowledged_at=NULL, resolved_at=NULL, resolution_note=NULL
			WHERE id = ?`
	default:
		return IncidentWorkflow{}, false, fmt.Errorf("%w %q (open|acknowledged|resolved)", ErrInvalidIncidentStatus, status)
	}
	defer func() { s.noteWrite("incident workflows", writeErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	defer tx.Rollback()
	storedID, err := resolveIncidentID(tx, id)
	if err == sql.ErrNoRows {
		s.noteRead("incident workflows", nil)
		return IncidentWorkflow{}, false, nil
	}
	if err != nil {
		s.noteRead("incident workflows", err)
		return IncidentWorkflow{}, false, err
	}
	res, err := tx.Exec(query, append(args, storedID)...)
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	if changed == 0 {
		return IncidentWorkflow{}, false, nil
	}
	wf, err := scanIncidentWorkflow(tx.QueryRow(
		`SELECT status, acknowledged_at, resolved_at, resolution_note FROM incidents WHERE id = ?`, storedID))
	s.noteRead("incident workflows", err)
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return IncidentWorkflow{}, false, err
	}
	return wf, true, nil
}

// IncidentStatus returns the workflow state for one incident.
func (s *Store) IncidentStatus(id string) (IncidentWorkflow, bool) {
	wf, found, _ := s.IncidentStatusResult(id)
	return wf, found
}

// IncidentStatusResult distinguishes a missing row from an unavailable or
// malformed workflow. Missing rows are healthy reads, not storage failures.
func (s *Store) IncidentStatusResult(id string) (workflow IncidentWorkflow, found bool, readErr error) {
	defer func() { s.noteRead("incident workflows", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()

	storedID, err := resolveIncidentID(s.db, id)
	if err == sql.ErrNoRows {
		return IncidentWorkflow{Status: "unknown"}, false, nil
	}
	if err != nil {
		return IncidentWorkflow{Status: "unknown"}, false, err
	}
	wf, err := scanIncidentWorkflow(s.db.QueryRow(
		`SELECT status, acknowledged_at, resolved_at, resolution_note FROM incidents WHERE id = ?`, storedID))
	if err != nil {
		return IncidentWorkflow{Status: "unknown"}, false, err
	}
	return wf, true, nil
}

func scanIncidentWorkflow(row *sql.Row) (IncidentWorkflow, error) {
	var wf IncidentWorkflow
	var ack, res, note sql.NullString
	if err := row.Scan(&wf.Status, &ack, &res, &note); err != nil {
		return IncidentWorkflow{}, err
	}
	switch wf.Status {
	case "open", "acknowledged", "resolved":
	default:
		return IncidentWorkflow{}, fmt.Errorf("invalid incident workflow status")
	}
	wf.AcknowledgedAt = ack.String
	wf.ResolvedAt = res.String
	wf.ResolutionNote = note.String
	return wf, nil
}

// SessionIncidents rejects partial history when a report's session identity
// disagrees with the storage scope used to select it.
func (s *Store) SessionIncidents(sessionID string) (out []model.IncidentReport, readErr error) {
	defer func() { s.noteRead("incident remediation", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id,report_json FROM incidents WHERE session_id=? ORDER BY `+timestampOrderExpr("created_at")+` DESC,id DESC LIMIT 100`, sessionID)
	if err != nil {
		return nil, err
	}
	list, err := scanIncidentsResult(rows)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].SessionID != sessionID {
			return nil, fmt.Errorf("incident session identity mismatch")
		}
		if err := s.attachIncidentRemediationLocked(&list[i]); err != nil {
			return nil, err
		}
	}
	return list, nil
}
