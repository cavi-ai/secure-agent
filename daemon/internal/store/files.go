package store

import (
	"encoding/json"
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
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.FileFinding{}
	like := jsonLike(path)

	rows, err := s.db.Query(`SELECT id, rule, severity, ts, agent, session_id, evidence, COALESCE(acknowledged, '')
		FROM flags WHERE evidence LIKE ? ESCAPE '\' ORDER BY ts DESC LIMIT ?`, like, pathScanCap)
	if err != nil {
		log.Printf("store: path findings (flags): %v", err)
		return out
	}
	flags := 0
	for rows.Next() && flags < limit {
		var f model.FileFinding
		var evJSON, ack string
		if rows.Scan(&f.ID, &f.Rule, &f.Severity, &f.TS, &f.Agent, &f.SessionID, &evJSON, &ack) != nil {
			continue
		}
		var ev []model.EvidenceItem
		if json.Unmarshal([]byte(evJSON), &ev) != nil ||
			!slices.ContainsFunc(ev, func(it model.EvidenceItem) bool { return it.Label == path }) {
			continue
		}
		f.Kind = "flag"
		f.Acknowledged = ack != ""
		out = append(out, f)
		flags++
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: path findings (flags) cursor: %v", err)
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT report_json, COALESCE(status, 'open') FROM incidents
		WHERE report_json LIKE ? ESCAPE '\' ORDER BY datetime(created_at) DESC LIMIT ?`, like, pathScanCap)
	if err != nil {
		log.Printf("store: path findings (incidents): %v", err)
		return out
	}
	defer rows.Close()
	incidents := 0
	for rows.Next() && incidents < limit {
		var reportJSON, status string
		if rows.Scan(&reportJSON, &status) != nil {
			continue
		}
		var inc model.IncidentReport
		if json.Unmarshal([]byte(reportJSON), &inc) != nil || !slices.Contains(inc.TouchedFiles, path) {
			continue
		}
		out = append(out, model.FileFinding{
			Kind: "incident", ID: inc.ID, Rule: inc.Rule, Risk: string(inc.Risk),
			TS: inc.Timestamp.UTC().Format(time.RFC3339Nano), Agent: inc.Agent, SessionID: inc.SessionID, Status: status,
		})
		incidents++
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: path findings (incidents) cursor: %v", err)
	}
	return out
}

// PathAccesses returns the newest file open/write/delete events on path made
// inside an agent session, at most limit. Never nil.
func (s *Store) PathAccesses(path string, limit int) []model.FileAccess {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.FileAccess{}
	rows, err := s.db.Query(`SELECT kind, ts, pid, COALESCE(exe_path, ''), session_id FROM events
		WHERE path = ? AND kind IN (?, ?, ?) AND COALESCE(session_id, '') != '' ORDER BY id DESC LIMIT ?`,
		path, int(event.KindFileOpen), int(event.KindFileWrite), int(event.KindFileDelete), normalizeLimit(limit))
	if err != nil {
		log.Printf("store: path accesses: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a model.FileAccess
		var kind int
		if rows.Scan(&kind, &a.TS, &a.PID, &a.ExePath, &a.SessionID) != nil {
			continue
		}
		a.Kind = event.Kind(kind).String()
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: path accesses cursor: %v", err)
	}
	return out
}
