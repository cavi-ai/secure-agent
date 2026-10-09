package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// SessionCoverageFact is observed metadata, never a protection verdict.
type SessionCoverageFact struct {
	ID, Harness, Workspace, RootStartedAt, Confidence              string
	RootPID                                                        int32
	HookLastSeen, TraceLastSeen, PayloadLastSeen, DecisionLastSeen string
}

// SessionCoverageSince reads only the selected live roots in one bounded
// SQLite snapshot. Session IDs, not process IDs, join evidence. Each window
// starts no earlier than the session itself and excludes future timestamps.
func (s *Store) SessionCoverageSince(pids []int32, since, until time.Time) (out []SessionCoverageFact, readErr error) {
	defer func() { s.noteRead("session coverage", readErr) }()
	if len(pids) == 0 {
		return []SessionCoverageFact{}, nil
	}
	if len(pids) > 128 {
		return nil, fmt.Errorf("too many coverage roots")
	}
	args := []any{}
	lower := since.UTC().Format(activityTimeLayout)
	upper := until.UTC().Format(activityTimeLayout)
	window := timestampOrderExpr("e.ts") + " >= max(?, " + timestampOrderExpr("s.started_at") + ") AND " + timestampOrderExpr("e.ts") + " <= ?"
	last := func(kinds string, extra string) string {
		args = append(args, lower, upper)
		return "COALESCE((SELECT substr(MAX(" + timestampOrderExpr("e.ts") + " || e.ts),31) FROM events e WHERE e.session_id=s.id AND e.kind IN (" + kinds + ") " + extra + " AND " + window + "),'')"
	}
	hook := last(fmt.Sprint(int(event.KindPluginAction)), "AND e.detail IN ('secret-guard:allow','secret-guard:deny','secret-guard-broker:allow','secret-guard-broker:deny')")
	trace := last(fmt.Sprintf("%d,%d,%d", event.KindToolCall, event.KindTurn, event.KindModelCall), "")
	payload := last(fmt.Sprint(int(event.KindProxyHit)), "AND (e.detail LIKE 'proxy-secret-leak:%' OR e.detail LIKE 'proxy-prompt-injection:%')")
	args = append(args, lower, upper)
	decision := `COALESCE((SELECT MAX(g.at) FROM guard_decisions g WHERE g.session_id=s.id AND g.at >= max(?, ` + timestampOrderExpr("s.started_at") + `) AND g.at <= ?),'')`
	for _, pid := range pids {
		args = append(args, pid)
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(pids)), ",")
	query := `SELECT s.id,s.harness,COALESCE(s.workspace,''),s.root_pid,COALESCE(s.root_started_at,''),COALESCE(s.confidence,''),` + hook + "," + trace + "," + payload + "," + decision + ` FROM sessions s WHERE s.root_pid IN (` + marks + `) AND s.status IN ('active','idle')`
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out = []SessionCoverageFact{}
	for rows.Next() {
		var f SessionCoverageFact
		if err := rows.Scan(&f.ID, &f.Harness, &f.Workspace, &f.RootPID, &f.RootStartedAt, &f.Confidence, &f.HookLastSeen, &f.TraceLastSeen, &f.PayloadLastSeen, &f.DecisionLastSeen); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, rows.Close()
}
