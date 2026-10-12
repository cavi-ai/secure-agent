package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// IncidentDetail is the report and its workflow from the same stored row.
type IncidentDetail struct {
	model.IncidentReport
	Workflow IncidentWorkflow `json:"workflow"`
}

const incidentDetailColumns = `id, report_json, status, acknowledged_at, resolved_at, resolution_note, COALESCE(remediation_json,'')`

type incidentScanner interface{ Scan(...any) error }

func scanIncidentDetail(row incidentScanner) (IncidentDetail, error) {
	var id, raw, remediation string
	var status, ack, resolved, note sql.NullString
	if err := row.Scan(&id, &raw, &status, &ack, &resolved, &note, &remediation); err != nil {
		return IncidentDetail{}, err
	}
	report, err := decodeIncidentReport(id, raw)
	if err != nil {
		return IncidentDetail{}, err
	}
	wf := IncidentWorkflow{Status: status.String, AcknowledgedAt: ack.String, ResolvedAt: resolved.String, ResolutionNote: note.String}
	if !status.Valid {
		return IncidentDetail{}, incidentWorkflowReadError{fmt.Errorf("unavailable incident workflow")}
	}
	if err := validateIncidentWorkflow(wf); err != nil {
		return IncidentDetail{}, incidentWorkflowReadError{err}
	}
	if _, err := projectIncidentRemediation(report, remediation); err != nil {
		return IncidentDetail{}, err
	}
	return IncidentDetail{IncidentReport: *report, Workflow: wf}, nil
}

type incidentWorkflowReadError struct{ error }

func (s *Store) noteIncidentDetailRead(err error) {
	var workflowErr incidentWorkflowReadError
	if errors.As(err, &workflowErr) {
		s.noteRead("incident workflows", err)
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	s.noteRead("incidents", err)
	if err == nil {
		s.noteRead("incident workflows", nil)
	}
}

// Advice is optional enrichment. Its batch read has separate health so an
// unavailable advisor table cannot erase readable incident evidence.
func (s *Store) attachIncidentDetailAdviceLocked(list []IncidentDetail) {
	if len(list) == 0 {
		return
	}
	args := make([]any, len(list))
	indices := make(map[string]int, len(list))
	for i := range list {
		args[i] = list[i].ID
		indices[list[i].ID] = i
	}
	rows, err := s.db.Query(`SELECT subject_id,confidence,rationale,created_at FROM advisor_verdicts WHERE kind='incident' AND subject_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+`)`, args...)
	if err != nil {
		s.noteRead(advisorReadKind("incident"), err)
		return
	}
	defer rows.Close()
	var readErr error
	for rows.Next() {
		var id, rationale string
		var confidence sql.NullFloat64
		var created sql.NullString
		err := rows.Scan(&id, &confidence, &rationale, &created)
		if err == nil && (math.IsNaN(confidence.Float64) || math.IsInf(confidence.Float64, 0)) {
			err = fmt.Errorf("invalid advisor confidence")
		}
		if err == nil && created.String != "" {
			_, err = time.Parse(time.RFC3339Nano, created.String)
		}
		if err != nil {
			if readErr == nil {
				readErr = err
			}
			continue
		}
		if i, ok := indices[id]; ok {
			list[i].AdvisorNarrative = rationale
		}
	}
	if err := rows.Err(); readErr == nil {
		readErr = err
	}
	s.noteRead(advisorReadKind("incident"), readErr)
}

func validateIncidentWorkflow(wf IncidentWorkflow) error {
	switch wf.Status {
	case "open", "acknowledged", "resolved":
		return nil
	}
	return fmt.Errorf("invalid incident workflow status")
}

// GetIncidentDetail selects exact IDs before flag aliases and reads the report,
// workflow and remediation together. Healthy absence remains sql.ErrNoRows.
func (s *Store) GetIncidentDetail(id string) (detail *IncidentDetail, readErr error) {
	defer func() { s.noteIncidentDetailRead(readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT `+incidentDetailColumns+` FROM incidents WHERE id=COALESCE(
		(SELECT id FROM incidents WHERE id=?),
		(SELECT id FROM incidents WHERE flag_id=? OR EXISTS (SELECT 1 FROM json_each(COALESCE(flag_ids,'[]')) WHERE value=?)
		 ORDER BY `+timestampOrderExpr("created_at")+` DESC,id DESC LIMIT 1))`, id, id, id)
	got, err := scanIncidentDetail(row)
	if err != nil {
		return nil, err
	}
	list := []IncidentDetail{got}
	s.attachIncidentDetailAdviceLocked(list)
	return &list[0], nil
}

func (s *Store) RecentIncidentDetails(limit int) (out []IncidentDetail, readErr error) {
	defer func() { s.noteIncidentDetailRead(readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.incidentDetailsLocked(`SELECT `+incidentDetailColumns+` FROM incidents WHERE (status IS NULL OR status!='resolved') ORDER BY `+timestampOrderExpr("created_at")+` DESC,id DESC LIMIT ?`, "", normalizeLimit(limit))
}

func (s *Store) SessionIncidentDetails(sessionID string) (out []IncidentDetail, readErr error) {
	defer func() { s.noteRead("incident remediation", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.incidentDetailsLocked(`SELECT `+incidentDetailColumns+` FROM incidents WHERE session_id=? ORDER BY `+timestampOrderExpr("created_at")+` DESC,id DESC LIMIT 100`, sessionID, sessionID)
}

func (s *Store) incidentDetailsLocked(query, sessionID string, args ...any) ([]IncidentDetail, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IncidentDetail{}
	for rows.Next() {
		got, err := scanIncidentDetail(rows)
		if err != nil {
			return nil, err
		}
		if sessionID != "" && got.SessionID != sessionID {
			return nil, fmt.Errorf("incident session identity mismatch")
		}
		out = append(out, got)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	s.attachIncidentDetailAdviceLocked(out)
	return out, nil
}
