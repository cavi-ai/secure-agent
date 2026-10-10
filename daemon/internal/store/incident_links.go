package store

import "database/sql"

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
	id, err = resolveIncidentWorkflowID(q, key)
	if err != nil {
		return id, reportJSON, err
	}
	err = q.QueryRow(`SELECT report_json FROM incidents WHERE id = ?`, id).Scan(&reportJSON)
	return id, reportJSON, err
}

// resolveIncidentWorkflowID follows incident detail identity precedence: an
// exact report ID wins; otherwise the newest report linked to the flag wins.
// Updates use their transaction here so selection and mutation stay together.
func resolveIncidentWorkflowID(q interface{ QueryRow(string, ...any) *sql.Row }, id string) (string, error) {
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
