package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// pathScanCap bounds the candidate rows a path lookup unmarshals.
const pathScanCap = 500

// jsonLike is a LIKE pattern matching path as it appears JSON-encoded inside
// a stored document; the caller re-checks every candidate exactly.
func jsonLike(path string) string {
	b, _ := json.Marshal(path)
	enc := strings.Trim(string(b), `"`)
	enc = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(enc)
	return "%" + enc + "%"
}

// PathFindings returns the flags whose evidence names path and the incidents
// whose touched files include it, newest first, at most limit of each.
// Never nil.
func (s *Store) PathFindings(path string, limit int) []model.FileFinding {
	out, err := s.PathFindingsResult(path, limit)
	if err != nil {
		log.Printf("store: path findings: %v", err)
		return []model.FileFinding{}
	}
	return out
}

// PathFindingsResult returns no partial findings when a query or candidate
// row cannot be read. A successful empty result is non-nil.
func (s *Store) PathFindingsResult(path string, limit int) (findings []model.FileFinding, readErr error) {
	defer func() { s.noteRead("path findings", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.FileFinding{}
	like := jsonLike(path)

	rows, err := s.db.Query(`SELECT id, rule, severity, ts, agent, session_id, evidence, COALESCE(acknowledged, '')
		FROM flags WHERE evidence LIKE ? ESCAPE '\' ORDER BY ts DESC LIMIT ?`, like, pathScanCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	flags := 0
	for rows.Next() && flags < limit {
		var f model.FileFinding
		var evJSON, ack string
		var rule, agent, sessionID sql.NullString
		if err := rows.Scan(&f.ID, &rule, &f.Severity, &f.TS, &agent, &sessionID, &evJSON, &ack); err != nil {
			return nil, err
		}
		f.Rule, f.Agent, f.SessionID = rule.String, agent.String, sessionID.String
		if _, err := time.Parse(time.RFC3339Nano, f.TS); err != nil {
			return nil, fmt.Errorf("invalid path finding timestamp")
		}
		var ev []model.EvidenceItem
		if err := json.Unmarshal([]byte(evJSON), &ev); err != nil {
			return nil, fmt.Errorf("decode path finding evidence: %w", err)
		}
		i := slices.IndexFunc(ev, func(it model.EvidenceItem) bool { return it.Label == path })
		if i < 0 {
			continue
		}
		f.Kind = "flag"
		f.EvidenceKind, f.EvidenceRule, f.Offset = ev[i].Kind, ev[i].Rule, ev[i].Offset
		f.Acknowledged = ack != ""
		out = append(out, f)
		flags++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT report_json, COALESCE(status, 'open') FROM incidents
		WHERE report_json LIKE ? ESCAPE '\' ORDER BY datetime(created_at) DESC LIMIT ?`, like, pathScanCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	incidents := 0
	for rows.Next() && incidents < limit {
		var reportJSON, status string
		if err := rows.Scan(&reportJSON, &status); err != nil {
			return nil, err
		}
		var inc model.IncidentReport
		if err := json.Unmarshal([]byte(reportJSON), &inc); err != nil {
			return nil, fmt.Errorf("decode path finding incident: %w", err)
		}
		if !slices.Contains(inc.TouchedFiles, path) {
			continue
		}
		out = append(out, model.FileFinding{
			Kind: "incident", ID: inc.ID, Rule: inc.Rule, Risk: string(inc.Risk),
			TS: inc.Timestamp.UTC().Format(time.RFC3339Nano), Agent: inc.Agent, SessionID: inc.SessionID, Status: status,
		})
		incidents++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// PathAccesses returns the newest file open/write/delete events on path made
// inside an agent session, at most limit. Never nil.
func (s *Store) PathAccesses(path string, limit int) []model.FileAccess {
	out, err := s.PathAccessesResult(path, limit)
	if err != nil {
		log.Printf("store: path accesses: %v", err)
		return []model.FileAccess{}
	}
	return out
}

// PathAccessesResult distinguishes unavailable access history from an empty
// history and discards partial results on failure.
func (s *Store) PathAccessesResult(path string, limit int) (accesses []model.FileAccess, readErr error) {
	defer func() { s.noteRead("path accesses", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.FileAccess{}
	rows, err := s.db.Query(`SELECT kind, ts, pid, COALESCE(exe_path, ''), session_id FROM events
		WHERE path = ? AND kind IN (?, ?, ?) AND COALESCE(session_id, '') != '' ORDER BY id DESC LIMIT ?`,
		path, int(event.KindFileOpen), int(event.KindFileWrite), int(event.KindFileDelete), normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a model.FileAccess
		var kind int
		if err := rows.Scan(&kind, &a.TS, &a.PID, &a.ExePath, &a.SessionID); err != nil {
			return nil, err
		}
		if _, err := time.Parse(time.RFC3339Nano, a.TS); err != nil {
			return nil, fmt.Errorf("invalid path access timestamp")
		}
		a.Kind = event.Kind(kind).String()
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
