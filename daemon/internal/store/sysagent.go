package store

import (
	"encoding/json"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// The system agent's chat, plans and runs (console Agent tab). Each row is
// its id, a timestamp and the JSON of the model type; content arrives
// masked (sysagent masks before it stores).
var sysAgentSchemas = []string{
	`CREATE TABLE IF NOT EXISTS sysagent_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL);`,
	`CREATE TABLE IF NOT EXISTS sysagent_plans (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL);`,
	`CREATE TABLE IF NOT EXISTS sysagent_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL);`,
}

// Bounds on the tables (rows come from console actions).
const (
	maxSysAgentMessages = 500
	maxSysAgentPlans    = 500
	maxSysAgentRuns     = 1000
)

// putSysAgentRow inserts v (id 0) or replaces row id, keeping the newest
// max rows. table is one of the constants above, never input.
func (s *Store) putSysAgentRow(table string, id int64, ts time.Time, v any, max int) int64 {
	body, err := json.Marshal(v)
	if err != nil {
		log.Printf("store: %s: %v", table, err)
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != 0 {
		if _, err := s.db.Exec(`UPDATE `+table+` SET body = ? WHERE id = ?`, string(body), id); err != nil {
			log.Printf("store: update %s %d: %v", table, id, err)
		}
		return id
	}
	res, err := s.db.Exec(`INSERT INTO `+table+` (ts, body) VALUES (?, ?)`, ts.UTC().Format(time.RFC3339Nano), string(body))
	if err != nil {
		log.Printf("store: insert %s: %v", table, err)
		return 0
	}
	_, _ = s.db.Exec(`DELETE FROM `+table+` WHERE id NOT IN (SELECT id FROM `+table+` ORDER BY id DESC LIMIT ?)`, max)
	id, _ = res.LastInsertId()
	return id
}

// getSysAgentRow decodes row id into v.
func (s *Store) getSysAgentRow(table string, id int64, v any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body string
	if err := s.db.QueryRow(`SELECT body FROM `+table+` WHERE id = ?`, id).Scan(&body); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(body), v); err != nil {
		log.Printf("store: %s %d: %v", table, id, err)
		return false
	}
	return true
}

// sysAgentRows calls each with the id and body of the newest limit rows,
// newest first.
func (s *Store) sysAgentRows(table string, limit int, each func(id int64, body []byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, body FROM `+table+` ORDER BY id DESC LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		log.Printf("store: query %s: %v", table, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var body string
		if rows.Scan(&id, &body) == nil {
			each(id, []byte(body))
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: %s cursor error (result may be truncated): %v", table, err)
	}
}

// PutSysAgentMessage inserts a chat message (ID 0) or rewrites it, and
// returns its id.
func (s *Store) PutSysAgentMessage(m model.SysAgentMessage) int64 {
	return s.putSysAgentRow("sysagent_messages", m.ID, m.TS, m, maxSysAgentMessages)
}

// GetSysAgentMessage returns one chat message.
func (s *Store) GetSysAgentMessage(id int64) (model.SysAgentMessage, bool) {
	var m model.SysAgentMessage
	ok := s.getSysAgentRow("sysagent_messages", id, &m)
	m.ID = id
	return m, ok
}

// SysAgentMessages returns the newest limit messages, oldest first (chat
// order).
func (s *Store) SysAgentMessages(limit int) []model.SysAgentMessage {
	out := []model.SysAgentMessage{}
	s.sysAgentRows("sysagent_messages", limit, func(id int64, body []byte) {
		var m model.SysAgentMessage
		if json.Unmarshal(body, &m) == nil {
			m.ID = id
			out = append(out, m)
		}
	})
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// ClearSysAgentMessages deletes the chat; plans and runs stay.
func (s *Store) ClearSysAgentMessages() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM sysagent_messages`); err != nil {
		log.Printf("store: clear sysagent_messages: %v", err)
	}
}

// PutSysAgentPlan inserts a plan (ID 0) or rewrites it, and returns its id.
// Ready and Reason are computed on read and never stored.
func (s *Store) PutSysAgentPlan(p model.SysAgentPlan) int64 {
	p.Ready, p.Reason = false, ""
	return s.putSysAgentRow("sysagent_plans", p.ID, p.CreatedAt, p, maxSysAgentPlans)
}

// GetSysAgentPlan returns one plan.
func (s *Store) GetSysAgentPlan(id int64) (model.SysAgentPlan, bool) {
	var p model.SysAgentPlan
	ok := s.getSysAgentRow("sysagent_plans", id, &p)
	p.ID = id
	return p, ok
}

// SysAgentPlans returns plans newest first.
func (s *Store) SysAgentPlans(limit int) []model.SysAgentPlan {
	out := []model.SysAgentPlan{}
	s.sysAgentRows("sysagent_plans", limit, func(id int64, body []byte) {
		var p model.SysAgentPlan
		if json.Unmarshal(body, &p) == nil {
			p.ID = id
			out = append(out, p)
		}
	})
	return out
}

// DeleteSysAgentPlan deletes a plan; false when there was none.
func (s *Store) DeleteSysAgentPlan(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM sysagent_plans WHERE id = ?`, id)
	if err != nil {
		log.Printf("store: delete sysagent plan %d: %v", id, err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// PutSysAgentRun inserts a run (ID 0) or rewrites it, and returns its id.
func (s *Store) PutSysAgentRun(r model.SysAgentRun) int64 {
	return s.putSysAgentRow("sysagent_runs", r.ID, r.TS, r, maxSysAgentRuns)
}

// SysAgentRuns returns runs newest first.
func (s *Store) SysAgentRuns(limit int) []model.SysAgentRun {
	out := []model.SysAgentRun{}
	s.sysAgentRows("sysagent_runs", limit, func(id int64, body []byte) {
		var r model.SysAgentRun
		if json.Unmarshal(body, &r) == nil {
			r.ID = id
			out = append(out, r)
		}
	})
	return out
}
