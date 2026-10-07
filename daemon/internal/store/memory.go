package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// MemoryCursor is the exclusive boundary for an earlier page.
type MemoryCursor struct {
	At         time.Time
	SourceRank int
	SourceID   string
}

// MemoryFact contains only structured fields needed to build an allowlisted
// summary. Raw paths, event detail, evidence, and incident narratives stay in
// their source tables.
type MemoryFact struct {
	ID             string
	SessionID      string
	At             time.Time
	SourceRank     int
	SourceID       string
	Kind           string
	EventKind      event.Kind
	Tool           string
	Model          string
	TokensIn       int64
	TokensOut      int64
	RuleID         string
	Severity       int
	SeverityText   string
	Risk           string
	Status         string
	Count          int
	Verdict        string
	Scope          string
	DiagnosisCodes []string
	RSSBytes       uint64
}

const (
	memoryActivityRank = 1
	memoryFlagRank     = 2
	memoryIncidentRank = 3
	memoryGuardRank    = 4
	memoryResourceRank = 5
)

// createMemoryIndexes runs after legacy session columns have been migrated.
// The query expressions below match these indexes exactly.
func createMemoryIndexes(db *sql.Tx) error {
	for _, spec := range []struct{ name, table, key, at, id string }{
		{"idx_memory_events", "events", "session_id", "ts", "id"},
		{"idx_memory_flags", "flags", "session_id", "ts", "id"},
		{"idx_memory_incidents", "incidents", "session_id", "created_at", "id"},
		{"idx_memory_guards", "guard_decisions", "session_id", "at", "id"},
		{"idx_memory_resources", "resource_episodes", "session_id", "captured_at", "id"},
		{"idx_memory_resource_families", "resource_episodes", "session_key", "captured_at", "id"},
	} {
		q := "CREATE INDEX IF NOT EXISTS " + spec.name + " ON " + spec.table + "(" + spec.key + ", " + memoryTimestampExpr(spec.at) + ", CAST(" + spec.id + " AS TEXT))"
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("create %s: %w", spec.name, err)
		}
	}
	return nil
}

// memoryRows limits each source before the cross-source merge. All SQL
// identifiers are fixed call-site constants; values remain bound parameters.
func memoryRows(tx *sql.Tx, table, atColumn, idColumn, extra, filter string, args []any, rank int, before *MemoryCursor, limit int) (*sql.Rows, error) {
	atExpr := memoryTimestampExpr(atColumn)
	idExpr := "CAST(" + idColumn + " AS TEXT)"
	where := "(" + filter + ") AND strftime('%s'," + atColumn + ") IS NOT NULL"
	if before != nil {
		boundary := before.At.UnixNano()
		switch {
		case rank < before.SourceRank:
			where += " AND " + atExpr + " <= ?"
			args = append(args, boundary)
		case rank > before.SourceRank:
			where += " AND " + atExpr + " < ?"
			args = append(args, boundary)
		default:
			where += " AND (" + atExpr + " < ? OR (" + atExpr + " = ? AND " + idExpr + " < ?))"
			args = append(args, boundary, boundary, before.SourceID)
		}
	}
	q := "SELECT " + idExpr + ", " + atExpr + ", " + extra + " FROM " + table + " WHERE " + where + " ORDER BY " + atExpr + " DESC, " + idExpr + " DESC LIMIT ?"
	args = append(args, limit+1)
	return tx.Query(q, args...)
}

func memoryBase(sessionID, kind, id string, ns int64, rank int) MemoryFact {
	return MemoryFact{ID: kind + ":" + id, SessionID: sessionID, At: time.Unix(0, ns).UTC(), SourceRank: rank, SourceID: id, Kind: kind}
}

// QuerySessionMemory reads a bounded newest page from each indexed source,
// merges them by the stable tuple, then returns the selected page oldest-first.
func (s *Store) QuerySessionMemory(sessionID string, before *MemoryCursor, limit int) ([]MemoryFact, bool, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	// Resolve old resource family identity before the read transaction. New
	// source rows always use their persisted session_id.
	legacyKey := "\x00"
	if sess, ok := s.GetSession(sessionID); ok && sess.RootPID > 0 && sess.RootStartedAt != "" {
		if started, err := time.Parse(time.RFC3339Nano, sess.RootStartedAt); err == nil {
			key := fmt.Sprintf("%d:%d", sess.RootPID, started.UnixNano())
			if s.SessionIDForFamilyKey(key) == sessionID {
				legacyKey = key
			}
		}
	}
	s.mu.Lock()
	retention := s.eventRetention
	s.mu.Unlock()
	if retention <= 0 {
		retention = DefaultEventRetention
	}
	guardCutoff := time.Now().Add(-retention).UnixNano()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	facts := make([]MemoryFact, 0, 5*(limit+1))
	if err = readMemoryActivity(tx, sessionID, before, limit, &facts); err != nil {
		return nil, false, err
	}
	if err = readMemoryFlags(tx, sessionID, before, limit, &facts); err != nil {
		return nil, false, err
	}
	if err = readMemoryIncidents(tx, sessionID, before, limit, &facts); err != nil {
		return nil, false, err
	}
	if err = readMemoryGuards(tx, sessionID, guardCutoff, before, limit, &facts); err != nil {
		return nil, false, err
	}
	if err = readMemoryResources(tx, sessionID, legacyKey, before, limit, &facts); err != nil {
		return nil, false, err
	}
	sort.Slice(facts, func(i, j int) bool {
		a, b := facts[i], facts[j]
		if !a.At.Equal(b.At) {
			return a.At.After(b.At)
		}
		if a.SourceRank != b.SourceRank {
			return a.SourceRank > b.SourceRank
		}
		return a.SourceID > b.SourceID
	})
	hasEarlier := len(facts) > limit
	if hasEarlier {
		facts = facts[:limit]
	}
	for i, j := 0, len(facts)-1; i < j; i, j = i+1, j-1 {
		facts[i], facts[j] = facts[j], facts[i]
	}
	return facts, hasEarlier, nil
}

func readMemoryActivity(tx *sql.Tx, sessionID string, before *MemoryCursor, limit int, out *[]MemoryFact) error {
	filter := "session_id = ? AND NOT (kind = ? AND COALESCE(detail,'') LIKE 'secret-guard-broker:%')"
	rows, err := memoryRows(tx, "events", "ts", "id", "kind, detail, path, tool, model, tokens_in, tokens_out", filter, []any{sessionID, int(event.KindPluginAction)}, memoryActivityRank, before, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ns, kind int64
		var detail, path, tool, model sql.NullString
		var in, outTokens sql.NullInt64
		if err := rows.Scan(&id, &ns, &kind, &detail, &path, &tool, &model, &in, &outTokens); err != nil {
			return err
		}
		f := memoryBase(sessionID, "activity", id, ns, memoryActivityRank)
		f.EventKind = event.Kind(kind)
		if kind == int64(event.KindPluginAction) && validGuardAudit(detail.String, path.String) {
			f.Kind = "guard-audit"
			f.ID = "guard-audit:" + id
			f.Verdict = strings.TrimPrefix(detail.String, "secret-guard:")
			f.RuleID = path.String
		} else {
			f.Tool = tool.String
			f.Model = model.String
			f.TokensIn = in.Int64
			f.TokensOut = outTokens.Int64
		}
		*out = append(*out, f)
	}
	return rows.Err()
}

func validMemoryIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 96 {
		return false
	}
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':' {
			continue
		}
		return false
	}
	return true
}

func validGuardAudit(detail, path string) bool {
	switch detail {
	case "secret-guard:allow":
		return strings.HasPrefix(path, "guard-allow:") && validMemoryIdentifier(strings.TrimPrefix(path, "guard-allow:")) || strings.HasPrefix(path, "guard-monitor:") && validMemoryIdentifier(strings.TrimPrefix(path, "guard-monitor:"))
	case "secret-guard:deny":
		return strings.HasPrefix(path, "guard-deny:") && validMemoryIdentifier(strings.TrimPrefix(path, "guard-deny:")) || path == "guard-config-corrupt"
	case "secret-guard:ask":
		return path == "guard-ask"
	default:
		return false
	}
}

func readMemoryFlags(tx *sql.Tx, sessionID string, before *MemoryCursor, limit int, out *[]MemoryFact) error {
	rows, err := memoryRows(tx, "flags", "ts", "id", "rule, severity", "session_id = ?", []any{sessionID}, memoryFlagRank, before, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ns int64
		var rule sql.NullString
		var severity sql.NullInt64
		if err := rows.Scan(&id, &ns, &rule, &severity); err != nil {
			return err
		}
		f := memoryBase(sessionID, "flag", id, ns, memoryFlagRank)
		f.RuleID = rule.String
		f.Severity = int(severity.Int64)
		*out = append(*out, f)
	}
	return rows.Err()
}

func readMemoryIncidents(tx *sql.Tx, sessionID string, before *MemoryCursor, limit int, out *[]MemoryFact) error {
	rows, err := memoryRows(tx, "incidents", "created_at", "id", "rule, risk, status, aggregate_count", "session_id = ?", []any{sessionID}, memoryIncidentRank, before, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ns int64
		var rule, risk, status sql.NullString
		var count sql.NullInt64
		if err := rows.Scan(&id, &ns, &rule, &risk, &status, &count); err != nil {
			return err
		}
		f := memoryBase(sessionID, "incident", id, ns, memoryIncidentRank)
		f.RuleID = rule.String
		f.Risk = risk.String
		f.Status = status.String
		f.Count = int(count.Int64)
		*out = append(*out, f)
	}
	return rows.Err()
}

func readMemoryGuards(tx *sql.Tx, sessionID string, cutoff int64, before *MemoryCursor, limit int, out *[]MemoryFact) error {
	filter := "session_id = ? AND " + memoryTimestampExpr("at") + " >= ?"
	rows, err := memoryRows(tx, "guard_decisions", "at", "id", "rule_id, verdict, scope", filter, []any{sessionID, cutoff}, memoryGuardRank, before, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ns int64
		var rule, verdict, scope sql.NullString
		if err := rows.Scan(&id, &ns, &rule, &verdict, &scope); err != nil {
			return err
		}
		f := memoryBase(sessionID, "guard", id, ns, memoryGuardRank)
		f.RuleID = rule.String
		f.Verdict = verdict.String
		f.Scope = scope.String
		*out = append(*out, f)
	}
	return rows.Err()
}

func readMemoryResources(tx *sql.Tx, sessionID, legacyKey string, before *MemoryCursor, limit int, out *[]MemoryFact) error {
	filter := "(session_id = ? OR (session_id IS NULL AND session_key = ?)) AND CASE WHEN json_valid(episode_json) THEN COALESCE(json_extract(episode_json,'$.session.kind'),'') ELSE '' END != 'infra'"
	rows, err := memoryRows(tx, "resource_episodes", "captured_at", "id", "severity, episode_json", filter, []any{sessionID, legacyKey}, memoryResourceRank, before, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ns int64
		var severity sql.NullString
		var payload string
		if err := rows.Scan(&id, &ns, &severity, &payload); err != nil {
			return err
		}
		f := memoryBase(sessionID, "resource", id, ns, memoryResourceRank)
		f.SeverityText = severity.String
		var structured struct {
			DiagnosisCodes []string `json:"diagnosis_codes"`
			Session        struct {
				RSSBytes uint64 `json:"rss_bytes"`
			} `json:"session"`
		}
		if json.Unmarshal([]byte(payload), &structured) == nil {
			f.DiagnosisCodes = structured.DiagnosisCodes
			f.RSSBytes = structured.Session.RSSBytes
		}
		*out = append(*out, f)
	}
	return rows.Err()
}
