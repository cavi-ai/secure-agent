package store

import (
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// MaxFileBatch bounds the transaction holding the store lock.
const MaxFileBatch = 64

const eventInsertColumns = ` INTO events (kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail, tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, provider, record)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func eventInsertArgs(e event.Event) []any {
	return []any{int(e.Kind), e.TS.UTC().Format(time.RFC3339Nano), e.PID, e.ExePath, e.SessionID, e.Path, e.RemoteHost, e.RemotePort, e.Detail,
		nullStr(e.ToolName), nullStr(e.ToolStatus), nullInt(e.DurationMs), nullStr(e.Model), nullInt(e.TokensIn), nullInt(e.TokensOut), nullFloat(e.CostUSD), nullStr(e.Provider), e.Record}
}

// PutFileEvents commits ordinary file activity and its rollups together.
// Security records and semantic traces retain their individual write path.
// A rejected batch has no partial effects; callers may retry rows individually.
func (s *Store) PutFileEvents(events []event.Event) (result WriteResult, err error) {
	if len(events) == 0 {
		return result, nil
	}
	if len(events) > MaxFileBatch {
		return result, fmt.Errorf("file batch exceeds %d events", MaxFileBatch)
	}
	for _, e := range events {
		if (e.Kind != event.KindFileOpen && e.Kind != event.KindFileWrite && e.Kind != event.KindFileDelete) || e.Record || e.CallID != "" {
			return result, fmt.Errorf("file batch contains a non-ordinary event")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { result.HealthChanged = s.noteWrite("events", err) }()
	tx, err := s.db.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	insert, err := tx.Prepare("INSERT" + eventInsertColumns)
	if err != nil {
		return result, err
	}
	defer insert.Close()
	rollup, err := tx.Prepare(`INSERT INTO rollup_hourly (bucket, kind, count) VALUES (?, ?, 1) ON CONFLICT(bucket, kind) DO UPDATE SET count=count+1`)
	if err != nil {
		return result, err
	}
	defer rollup.Close()
	for _, e := range events {
		s.aliasSessionLocked(&e)
		res, writeErr := insert.Exec(eventInsertArgs(e)...)
		if writeErr != nil {
			return result, writeErr
		}
		n, writeErr := res.RowsAffected()
		if writeErr != nil {
			return result, writeErr
		}
		if n != 1 {
			return result, fmt.Errorf("file batch write affected %d rows", n)
		}
		if _, err = rollup.Exec(rollupBucket(e.TS), "event:"+e.Kind.String()); err != nil {
			return result, err
		}
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	for _, e := range events {
		s.recordEventActivityLocked(e)
	}
	result.Changed = true
	return result, nil
}
