package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Only routing and retention metadata remains outside authenticated ciphertext.
var sysAgentSchemas = []string{
	`CREATE TABLE IF NOT EXISTS sysagent_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}');`,
	`CREATE TABLE IF NOT EXISTS sysagent_plans (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}');`,
	`CREATE TABLE IF NOT EXISTS sysagent_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}');`,
	`CREATE TABLE IF NOT EXISTS sysagent_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}');`,
	`CREATE TABLE IF NOT EXISTS sysagent_memory (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, body TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}');`,
}

const (
	maxSysAgentMessages = 500
	maxSysAgentPlans    = 500
	maxSysAgentRuns     = 1000
)

func (s *Store) agentMetadata(table string, body []byte) string {
	if table == "sysagent_memory" {
		var f model.SysAgentMemory
		if json.Unmarshal(body, &f) != nil {
			return "{}"
		}
		h := hmac.New(sha256.New, s.agentIndexKey[:])
		h.Write([]byte(f.Scope))
		meta, _ := json.Marshal(map[string]string{"scope": hex.EncodeToString(h.Sum(nil))})
		return string(meta)
	}

	if table != "sysagent_messages" {
		return "{}"
	}
	var m model.SysAgentMessage
	if json.Unmarshal(body, &m) != nil {
		return "{}"
	}
	meta, _ := json.Marshal(struct {
		Role   string `json:"role"`
		Origin string `json:"origin"`
		Review string `json:"review_state"`
	}{m.Role, m.Origin, m.ReviewState})
	return string(meta)
}

func (s *Store) putSysAgentRow(table string, id int64, ts time.Time, v any, max int) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentCryptoMu.RLock()
	defer s.agentCryptoMu.RUnlock()
	if s.agentLocked {
		return 0
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0
	}
	defer tx.Rollback()
	if id != 0 && table == "sysagent_messages" {
		var old, meta string
		if tx.QueryRow("SELECT body,meta FROM "+table+" WHERE id=?", id).Scan(&old, &meta) != nil {
			return 0
		}
		data, err := s.openAgentRow(table, id, meta, old)
		if err != nil {
			return 0
		}
		var prior model.SysAgentMessage
		if json.Unmarshal(data, &prior) != nil {
			return 0
		}
		m, ok := v.(model.SysAgentMessage)
		if !ok {
			return 0
		}
		if prior.LocalRunID != 0 && m.LocalRunID == 0 {
			m.LocalRunID = prior.LocalRunID
		}
		if prior.ReviewState == "saved" || prior.ReviewState == "dismissed" || prior.ReviewState == "approved" {
			m.ReviewState = prior.ReviewState
		}
		v = m
	}
	body, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	if id == 0 {
		res, err := tx.Exec("INSERT INTO "+table+"(ts,body) VALUES (?, '')", ts.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return 0
		}
		id, err = res.LastInsertId()
		if err != nil {
			return 0
		}
	}
	meta := s.agentMetadata(table, body)
	encoded, err := s.sealAgentRow(table, id, meta, body)
	if err != nil {
		return 0
	}
	res, err := tx.Exec("UPDATE "+table+" SET body=?,meta=?,ts=? WHERE id=?", encoded, meta, ts.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return 0
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0
	}
	query := "DELETE FROM " + table + " WHERE id NOT IN (SELECT id FROM " + table + " ORDER BY id DESC LIMIT ?)"
	if table == "sysagent_messages" {
		query += ` AND NOT (json_extract(meta,'$.origin')='analysis' AND json_extract(meta,'$.role')='assistant' AND COALESCE(NULLIF(json_extract(meta,'$.review_state'),''),'pending')='pending')`
	}
	if _, err = tx.Exec(query, max); err != nil {
		return 0
	}
	if tx.Commit() != nil {
		return 0
	}
	return id
}

func (s *Store) getSysAgentRow(table string, id int64, v any) bool {
	s.agentCryptoMu.RLock()
	defer s.agentCryptoMu.RUnlock()
	if s.agentLocked {
		return false
	}
	var raw, meta string
	if s.db.QueryRow("SELECT body,meta FROM "+table+" WHERE id=?", id).Scan(&raw, &meta) != nil {
		return false
	}
	body, err := s.openAgentRow(table, id, meta, raw)
	return err == nil && json.Unmarshal(body, v) == nil
}

func (s *Store) sysAgentRows(table string, limit int, each func(int64, []byte)) {
	s.agentCryptoMu.RLock()
	defer s.agentCryptoMu.RUnlock()
	if s.agentLocked {
		return
	}
	rows, err := s.db.Query("SELECT id,body,meta FROM "+table+" ORDER BY id DESC LIMIT ?", normalizeLimit(limit))
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var raw, meta string
		if rows.Scan(&id, &raw, &meta) == nil {
			body, err := s.openAgentRow(table, id, meta, raw)
			if err == nil {
				each(id, body)
			} else {
				log.Printf("store: encrypted agent record unavailable: %s/%d", table, id)
			}
		}
	}
}

func (s *Store) PutSysAgentMessage(m model.SysAgentMessage) int64 {
	return s.putSysAgentRow("sysagent_messages", m.ID, m.TS, m, maxSysAgentMessages)
}
func (s *Store) GetSysAgentMessage(id int64) (model.SysAgentMessage, bool) {
	var m model.SysAgentMessage
	ok := s.getSysAgentRow("sysagent_messages", id, &m)
	m.ID = id
	return m, ok
}
func (s *Store) SysAgentMessages(limit int) []model.SysAgentMessage {
	out := []model.SysAgentMessage{}
	s.sysAgentRows("sysagent_messages", limit, func(id int64, b []byte) {
		var m model.SysAgentMessage
		if json.Unmarshal(b, &m) == nil {
			m.ID = id
			out = append(out, m)
		}
	})
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// mutateAgentMessage uses one immediate SQLite transaction across decrypt,
// validation and replacement. Independent store handles cannot claim twice.
func (s *Store) mutateAgentMessage(id int64, change func(*model.SysAgentMessage) bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentCryptoMu.RLock()
	defer s.agentCryptoMu.RUnlock()
	if s.agentLocked {
		return false
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	var raw, meta string
	if tx.QueryRow("SELECT body,meta FROM sysagent_messages WHERE id=?", id).Scan(&raw, &meta) != nil {
		return false
	}
	body, err := s.openAgentRow("sysagent_messages", id, meta, raw)
	if err != nil {
		return false
	}
	var m model.SysAgentMessage
	if json.Unmarshal(body, &m) != nil || !change(&m) {
		return false
	}
	body, err = json.Marshal(m)
	if err != nil {
		return false
	}
	meta = s.agentMetadata("sysagent_messages", body)
	raw, err = s.sealAgentRow("sysagent_messages", id, meta, body)
	if err != nil {
		return false
	}
	if _, err = tx.Exec("UPDATE sysagent_messages SET body=?,meta=? WHERE id=?", raw, meta, id); err != nil {
		return false
	}
	return tx.Commit() == nil
}
func (s *Store) ClaimSysAgentAction(id int64) bool {
	return s.mutateAgentMessage(id, func(m *model.SysAgentMessage) bool {
		if m.Role != "assistant" || m.LocalCommand == nil || m.LocalRunID != 0 || (m.Origin == "analysis" && m.ReviewState != "" && m.ReviewState != "pending") {
			return false
		}
		m.LocalRunID = -1
		return true
	})
}
func (s *Store) ClearSysAgentMessages() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM sysagent_messages WHERE COALESCE(json_extract(meta,'$.origin'),'')!='analysis' OR COALESCE(json_extract(meta,'$.role'),'')!='assistant'`)
	if err != nil {
		log.Printf("store: clear agent chat failed")
	}
}
func (s *Store) SysAgentRecommendations(limit int) []model.SysAgentMessage {
	pending := []model.SysAgentMessage{}
	other := []model.SysAgentMessage{}
	// Table retention plus the bounded pending queue limits this scan.
	for _, m := range s.SysAgentMessages(maxSysAgentMessages + 100) {
		if m.Origin == "analysis" && m.Role == "assistant" {
			if m.ReviewState == "" || m.ReviewState == "pending" {
				pending = append([]model.SysAgentMessage{m}, pending...)
			} else {
				other = append([]model.SysAgentMessage{m}, other...)
			}
		}
	}
	out := append(pending, other...)
	return out[:min(len(out), normalizeLimit(limit))]
}
func (s *Store) PendingSysAgentRecommendations() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sysagent_messages WHERE json_extract(meta,'$.origin')='analysis' AND json_extract(meta,'$.role')='assistant' AND COALESCE(NULLIF(json_extract(meta,'$.review_state'),''),'pending')='pending'`).Scan(&n)
	return n
}
func (s *Store) SetSysAgentRecommendationState(id int64, state string) bool {
	if state != "saved" && state != "dismissed" && state != "approved" {
		return false
	}
	return s.mutateAgentMessage(id, func(m *model.SysAgentMessage) bool {
		if m.Origin != "analysis" || m.Role != "assistant" || (m.ReviewState != "" && m.ReviewState != "pending") {
			return false
		}
		m.ReviewState = state
		return true
	})
}
func (s *Store) PutSysAgentPlan(p model.SysAgentPlan) int64 {
	p.Ready = false
	p.Reason = ""
	return s.putSysAgentRow("sysagent_plans", p.ID, p.CreatedAt, p, maxSysAgentPlans)
}
func (s *Store) GetSysAgentPlan(id int64) (model.SysAgentPlan, bool) {
	var p model.SysAgentPlan
	ok := s.getSysAgentRow("sysagent_plans", id, &p)
	p.ID = id
	return p, ok
}
func (s *Store) SysAgentPlans(limit int) []model.SysAgentPlan {
	out := []model.SysAgentPlan{}
	s.sysAgentRows("sysagent_plans", limit, func(id int64, b []byte) {
		var p model.SysAgentPlan
		if json.Unmarshal(b, &p) == nil {
			p.ID = id
			out = append(out, p)
		}
	})
	return out
}
func (s *Store) DeleteSysAgentPlan(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("DELETE FROM sysagent_plans WHERE id=?", id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}
func (s *Store) PutSysAgentRun(r model.SysAgentRun) int64 {
	return s.putSysAgentRow("sysagent_runs", r.ID, r.TS, r, maxSysAgentRuns)
}
func (s *Store) SysAgentRuns(limit int) []model.SysAgentRun {
	out := []model.SysAgentRun{}
	s.sysAgentRows("sysagent_runs", limit, func(id int64, b []byte) {
		var r model.SysAgentRun
		if json.Unmarshal(b, &r) == nil {
			r.ID = id
			out = append(out, r)
		}
	})
	return out
}

func (s *Store) PutSysAgentSession(v model.SysAgentSession) int64 {
	return s.putSysAgentRow("sysagent_sessions", v.ID, v.OpenedAt, v, 100)
}
func (s *Store) SysAgentSessions() []model.SysAgentSession {
	out := []model.SysAgentSession{}
	s.sysAgentRows("sysagent_sessions", 100, func(id int64, b []byte) {
		var v model.SysAgentSession
		if json.Unmarshal(b, &v) == nil {
			v.ID = id
			out = append(out, v)
		}
	})
	return out
}
func (s *Store) PutSysAgentMemory(v model.SysAgentMemory) int64 {
	id := s.putSysAgentRow("sysagent_memory", v.ID, v.At, v, 500)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.db.Exec("DELETE FROM sysagent_memory WHERE "+instantBeforeSQL("ts"), instantBound(time.Now().Add(-90*24*time.Hour))...)
	return id
}

// FindSysAgentMemory uses a keyed scope index; paths and summaries are never
// copied into a plaintext full-text index.
func (s *Store) FindSysAgentMemory(scope string) []model.SysAgentMemory {
	s.agentCryptoMu.RLock()
	defer s.agentCryptoMu.RUnlock()
	out := []model.SysAgentMemory{}
	if s.agentLocked {
		return out
	}
	h := hmac.New(sha256.New, s.agentIndexKey[:])
	h.Write([]byte(scope))
	rows, err := s.db.Query("SELECT id,body,meta FROM sysagent_memory WHERE json_extract(meta,'$.scope')=? ORDER BY id DESC LIMIT 500", hex.EncodeToString(h.Sum(nil)))
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var raw, meta string
		if rows.Scan(&id, &raw, &meta) != nil {
			continue
		}
		b, err := s.openAgentRow("sysagent_memory", id, meta, raw)
		if err != nil {
			continue
		}
		var v model.SysAgentMemory
		if json.Unmarshal(b, &v) == nil && time.Since(v.At) < 90*24*time.Hour {
			v.ID = id
			out = append(out, v)
		}
	}
	return out
}
func (s *Store) SysAgentMemory() []model.SysAgentMemory {
	out := []model.SysAgentMemory{}
	s.sysAgentRows("sysagent_memory", 500, func(id int64, b []byte) {
		var v model.SysAgentMemory
		if json.Unmarshal(b, &v) == nil {
			v.ID = id
			if time.Since(v.At) < 90*24*time.Hour {
				out = append(out, v)
			}
		}
	})
	return out
}
func (s *Store) ForgetSysAgentMemory() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM sysagent_memory"); err != nil {
		return err
	}
	return tx.Commit()
}
