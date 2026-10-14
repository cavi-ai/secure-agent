package store

import (
	"errors"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/hookhealth"
)

const hookEvidenceLimit = 100

var ErrHookEvidenceQuery = errors.New("invalid hook evidence query")

type HookEvidenceFilter struct {
	Harness    string `json:"harness"`
	Event      string `json:"event"`
	EventScope string `json:"event_scope"`
	HandlerID  string `json:"handler_id"`
	ConfigID   string `json:"config_id"`
	Script     string `json:"script"`
}

type HookEvidencePage struct {
	SessionID string             `json:"session_id"`
	Filter    HookEvidenceFilter `json:"filter"`
	Since     time.Time          `json:"since"`
	Until     time.Time          `json:"until"`
	Rows      []HookEvidenceRun  `json:"rows"`
	Truncated bool               `json:"truncated"`
}

type HookEvidenceRun struct {
	ID         string            `json:"id"`
	TS         time.Time         `json:"ts"`
	Status     string            `json:"status"`
	DurationMs *int64            `json:"duration_ms,omitempty"`
	Chars      *int64            `json:"chars,omitempty"`
	Evidence   *hookrun.Evidence `json:"evidence,omitempty"`
}

// SessionHookEvidence reads one exact history group in a bounded recent window.
// Native output, commands and source paths are never selected. A tied timestamp
// is displayed with stable ID ordering, not as proof of execution chronology.
func (s *Store) SessionHookEvidence(session string, f HookEvidenceFilter, now time.Time) (out HookEvidencePage, readErr error) {
	if f.EventScope == "" {
		f.EventScope = "group"
	}
	if f.EventScope != "group" && f.EventScope != "exact" || f.EventScope == "group" && strings.Contains(f.Event, ":") {
		return out, ErrHookEvidenceQuery
	}
	check := hookrun.Record{Type: "hook_run", Version: 2, Harness: f.Harness, SessionID: session, ID: "query", TS: now, Event: f.Event, Script: f.Script, Status: "ok", Evidence: &hookrun.Evidence{HandlerID: f.HandlerID, ConfigID: f.ConfigID}}
	if check.Validate() != nil {
		return out, ErrHookEvidenceQuery
	}
	defer func() { s.noteRead("hook evidence", readErr) }()
	out = HookEvidencePage{SessionID: session, Filter: f, Since: now.Add(-hookhealth.Window), Until: now, Rows: []HookEvidenceRun{}}
	s.mu.Lock()
	defer s.mu.Unlock()
	eventColumn := "(CASE WHEN instr(hook,':')>0 THEN substr(hook,1,instr(hook,':')-1) ELSE hook END)"
	if f.EventScope == "exact" {
		eventColumn = "hook"
	}
	rows, err := s.db.Query(`SELECT run_id,ts,status,duration_ms,chars,evidence_json FROM hook_runs
		WHERE session_id=? AND harness=?
		AND `+eventColumn+`=?
		AND script=? AND COALESCE(json_extract(evidence_json,'$.handler_id'),'')=? AND COALESCE(json_extract(evidence_json,'$.config_id'),'')=?
		AND `+timestampOrderExpr("ts")+`>=? AND `+timestampOrderExpr("ts")+`<=?
		ORDER BY `+timestampOrderExpr("ts")+` DESC,run_id ASC LIMIT ?`, session, f.Harness, f.Event, f.Script, f.HandlerID, f.ConfigID,
		out.Since.UTC().Format("2006-01-02T15:04:05.000000000Z"), now.UTC().Format("2006-01-02T15:04:05.000000000Z"), hookEvidenceLimit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var run HookEvidenceRun
		var ts, metadata string
		var duration, chars int64
		if err := rows.Scan(&run.ID, &ts, &run.Status, &duration, &chars, &metadata); err != nil {
			return out, err
		}
		run.TS, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return out, errors.New("invalid hook evidence timestamp")
		}
		run.Evidence, err = decodeHookEvidence(metadata)
		if err != nil {
			return out, errors.New("invalid retained hook evidence")
		}
		check.ID, check.TS, check.Status, check.DurationMs, check.Chars = run.ID, run.TS, run.Status, duration, chars
		if check.Validate() != nil {
			return out, errors.New("invalid retained hook metadata")
		}
		if run.Evidence != nil && run.Evidence.DurationKnown || run.Evidence == nil && duration > 0 {
			run.DurationMs = &duration
		}
		if run.Evidence != nil && run.Evidence.CharsKnown || run.Evidence == nil && chars > 0 {
			run.Chars = &chars
		}
		out.Rows = append(out.Rows, run)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Rows) > hookEvidenceLimit {
		out.Truncated = true
		out.Rows = out.Rows[:hookEvidenceLimit]
	}
	return out, nil
}
