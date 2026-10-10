package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

var ErrStaleIncidentRemediation = errors.New("incident remediation changed")
var ErrInvalidIncidentRemediation = errors.New("invalid incident remediation")

type remediationReport struct {
	StepID     string     `json:"step_id"`
	Status     string     `json:"status"`
	ReportedAt *time.Time `json:"reported_at,omitempty"`
}
type remediationState struct {
	Revision int                 `json:"revision"`
	Reports  []remediationReport `json:"reports"`
}

func remediationHash(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func projectIncidentRemediation(inc *model.IncidentReport, raw string) (remediationState, error) {
	state := remediationState{Reports: []remediationReport{}}
	if raw != "" {
		var saved *remediationState
		if err := json.Unmarshal([]byte(raw), &saved); err != nil {
			return state, err
		}
		if saved == nil {
			return state, fmt.Errorf("null remediation state")
		}
		state = *saved
		if state.Revision < 0 || state.Reports == nil {
			return state, fmt.Errorf("invalid remediation state")
		}
	}
	copy := *inc
	copy.Remediation, copy.AdvisorNarrative = nil, ""
	view := &model.IncidentRemediation{Revision: state.Revision, EvidenceRevision: remediationHash(copy), Steps: []model.IncidentRemediationStep{}}
	reports := map[string]remediationReport{}
	for _, record := range state.Reports {
		if len(record.StepID) != 64 || (record.Status != "reported" && record.Status != "pending") || (record.Status == "reported" && (record.ReportedAt == nil || record.ReportedAt.IsZero())) {
			return state, fmt.Errorf("invalid remediation report")
		}
		if _, duplicate := reports[record.StepID]; duplicate {
			return state, fmt.Errorf("duplicate remediation report")
		}
		reports[record.StepID] = record
	}
	seen := map[string]bool{}
	for _, item := range inc.RotateList {
		// Incomplete historic advice does not identify an actionable step.
		if item.Name == "" || item.Action == "" {
			continue
		}
		id := remediationHash(item)
		if seen[id] {
			continue
		}
		seen[id] = true
		step := model.IncidentRemediationStep{ID: id, Item: item, Status: "pending", Verification: "unverified"}
		if r, ok := reports[id]; ok {
			step.Status, step.ReportedAt = r.Status, r.ReportedAt
			latest := inc.Timestamp
			if inc.LastFlagAt != nil && inc.LastFlagAt.After(latest) {
				latest = *inc.LastFlagAt
			}
			step.NewerEvidence = r.ReportedAt != nil && latest.After(*r.ReportedAt)
		}
		view.Steps = append(view.Steps, step)
	}
	inc.Remediation = view
	return state, nil
}

func (s *Store) attachIncidentRemediationLocked(inc *model.IncidentReport) error {
	var raw string
	if err := s.db.QueryRow(`SELECT COALESCE(remediation_json,'') FROM incidents WHERE id=?`, inc.ID).Scan(&raw); err != nil {
		return err
	}
	_, err := projectIncidentRemediation(inc, raw)
	return err
}

// ReportIncidentRemediation commits operator bookkeeping against the exact
// evidence and remediation revision viewed. It never executes external work,
// verifies a credential, acknowledges evidence, or resolves the incident.
func (s *Store) ReportIncidentRemediation(req model.IncidentRemediationRequest) (out *model.IncidentReport, writeErr error) {
	if req.ID == "" || len(req.StepID) != 64 || req.ExpectedRevision < 0 || len(req.ExpectedEvidence) != 64 || (req.Status != "reported" && req.Status != "pending") {
		return nil, ErrInvalidIncidentRemediation
	}
	defer func() {
		if errors.Is(writeErr, ErrStaleIncidentRemediation) || errors.Is(writeErr, ErrInvalidIncidentRemediation) || errors.Is(writeErr, sql.ErrNoRows) {
			return
		}
		s.noteWrite("incident remediation", writeErr)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var reportJSON, raw string
	if err := tx.QueryRowContext(ctx, `SELECT report_json,COALESCE(remediation_json,'') FROM incidents WHERE id=?`, req.ID).Scan(&reportJSON, &raw); err != nil {
		return nil, err
	}
	inc, err := decodeIncidentReport(req.ID, reportJSON)
	if err != nil {
		return nil, err
	}
	state, err := projectIncidentRemediation(inc, raw)
	if err != nil {
		return nil, err
	}
	if state.Revision != req.ExpectedRevision || inc.Remediation.EvidenceRevision != req.ExpectedEvidence {
		return nil, ErrStaleIncidentRemediation
	}
	found := false
	for _, step := range inc.Remediation.Steps {
		if step.ID == req.StepID {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrInvalidIncidentRemediation
	}
	record := remediationReport{StepID: req.StepID, Status: req.Status}
	if req.Status == "reported" {
		now := time.Now().UTC()
		record.ReportedAt = &now
	}
	replaced := false
	for i := range state.Reports {
		if state.Reports[i].StepID == record.StepID {
			state.Reports[i], replaced = record, true
			break
		}
	}
	if !replaced {
		state.Reports = append(state.Reports, record)
	}
	state.Revision++
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE incidents SET remediation_json=? WHERE id=? AND COALESCE(remediation_json,'')=? AND report_json=?`, string(data), req.ID, raw, reportJSON)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrStaleIncidentRemediation
	}
	// Read the stored result before commit: malformed writes must roll back.
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(remediation_json,'') FROM incidents WHERE id=?`, req.ID).Scan(&raw); err != nil {
		return nil, err
	}
	if raw != string(data) {
		return nil, fmt.Errorf("remediation result changed during write")
	}
	if _, err := projectIncidentRemediation(inc, raw); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return inc, nil
}

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
		if err := s.attachIncidentRemediationLocked(&list[i]); err != nil {
			return nil, err
		}
	}
	return list, nil
}
