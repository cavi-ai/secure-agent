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

func (s *Store) incidentIDForFlagLocked(flagID string) (string, bool, error) {
	if flagID == "" {
		return "", false, nil
	}
	var id, raw string
	err := s.db.QueryRow(`SELECT id,report_json FROM incidents
		WHERE flag_id = ? OR EXISTS (SELECT 1 FROM json_each(COALESCE(flag_ids,'[]')) WHERE value = ?)
		ORDER BY `+timestampOrderExpr("created_at")+` DESC, id DESC LIMIT 1`, flagID, flagID).Scan(&id, &raw)
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
