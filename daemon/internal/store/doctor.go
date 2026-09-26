package store

import (
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Read-only stats behind GET /doctor. Each answers one coverage question
// about the stored data; none of them writes.

// KindRetention is one event kind's stored row count against its row budget,
// and its record rows (event.Record) against theirs.
type KindRetention struct {
	Kind   int
	Name   string
	Rows   int // every row of the kind, record rows included
	Budget int
	// HorizonTS is the RFC3339 UTC time of the Budget-th newest row: how far
	// back the row cap keeps the kind. "" while the kind is under budget.
	HorizonTS string
	// Ring: the kind's newest Budget rows cover minutes under load; only its
	// record rows are expected to keep a day.
	Ring         bool
	RecordRows   int
	RecordBudget int
	// RecordHorizonTS is HorizonTS for the record rows alone.
	RecordHorizonTS string
}

func (s *Store) doctorCount(q string, args ...any) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		log.Printf("store: doctor count error: %v", err)
	}
	return n
}

func (s *Store) doctorCountByKey(q string, args ...any) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		log.Printf("store: doctor group error: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if rows.Scan(&k, &n) == nil {
			out[k] = n
		}
	}
	return out
}

func sinceArg(since time.Time) string { return since.UTC().Format(time.RFC3339Nano) }

// SessionIdentityStats returns the all-time session count and how many carry
// a harness name, plus, among named sessions started at or after since, how
// many carry a workspace and how many of those also carry a repo.
func (s *Store) SessionIdentityStats(since time.Time) (total, named, withWorkspace, withRepo int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	arg := sinceArg(since)
	err := s.db.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN COALESCE(harness,'') != '' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN COALESCE(harness,'') != '' AND COALESCE(workspace,'') != ''
			AND datetime(started_at) >= datetime(?) THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN COALESCE(harness,'') != '' AND COALESCE(workspace,'') != '' AND COALESCE(repo,'') != ''
			AND datetime(started_at) >= datetime(?) THEN 1 ELSE 0 END),0)
		FROM sessions`, arg, arg).Scan(&total, &named, &withWorkspace, &withRepo)
	if err != nil {
		log.Printf("store: session identity stats error: %v", err)
	}
	return total, named, withWorkspace, withRepo
}

// SessionsCreatedSince counts sessions started at or after since.
func (s *Store) SessionsCreatedSince(since time.Time) int {
	return s.doctorCount(`SELECT COUNT(*) FROM sessions WHERE datetime(started_at) >= datetime(?)`, sinceArg(since))
}

// ToolCallStats returns the all-time number of (session_id, call_id) pairs
// stored more than once, and the number of tool-call rows at or after since
// with no call id (a start and its completion can never pair).
func (s *Store) ToolCallStats(since time.Time) (dupePairs, idlessSince int) {
	dupePairs = s.doctorCount(`SELECT COUNT(*) FROM (SELECT 1 FROM events
		WHERE call_id IS NOT NULL AND call_id != ''
		GROUP BY session_id, call_id HAVING COUNT(*) > 1)`)
	idlessSince = s.doctorCount(`SELECT COUNT(*) FROM events
		WHERE kind = ? AND datetime(ts) >= datetime(?) AND (call_id IS NULL OR call_id = '')`,
		int(event.KindToolCall), sinceArg(since))
	return dupePairs, idlessSince
}

// PricingStats counts model calls: Claude-model calls with and without a
// cost, and all calls without a cost out of all calls.
func (s *Store) PricingStats() (claudePriced, claudeUnpriced, allUnpriced, allCalls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN model LIKE 'claude-%' AND cost_usd > 0 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN model LIKE 'claude-%' AND (cost_usd IS NULL OR cost_usd = 0) THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN cost_usd IS NULL OR cost_usd = 0 THEN 1 ELSE 0 END),0),
		COUNT(*)
		FROM events WHERE kind = ?`, int(event.KindModelCall)).
		Scan(&claudePriced, &claudeUnpriced, &allUnpriced, &allCalls)
	if err != nil {
		log.Printf("store: pricing stats error: %v", err)
	}
	return claudePriced, claudeUnpriced, allUnpriced, allCalls
}

// HookEventsSince counts harness hook events (plugin actions) at or after
// since.
func (s *Store) HookEventsSince(since time.Time) int {
	return s.doctorCount(`SELECT COUNT(*) FROM events WHERE kind = ? AND datetime(ts) >= datetime(?)`,
		int(event.KindPluginAction), sinceArg(since))
}

// TraceRowsByHarness counts trace rows (tool calls, turns, model calls) at or
// after since, keyed by their session's harness. Rows without a named session
// are not counted.
func (s *Store) TraceRowsByHarness(since time.Time) map[string]int {
	return s.doctorCountByKey(`SELECT s.harness, COUNT(*) FROM events e JOIN sessions s ON s.id = e.session_id
		WHERE e.kind IN (?, ?, ?) AND datetime(e.ts) >= datetime(?) AND COALESCE(s.harness,'') != ''
		GROUP BY s.harness`,
		int(event.KindToolCall), int(event.KindTurn), int(event.KindModelCall), sinceArg(since))
}

// SessionsByHarness counts named sessions started at or after since, keyed by
// harness.
func (s *Store) SessionsByHarness(since time.Time) map[string]int {
	return s.doctorCountByKey(`SELECT harness, COUNT(*) FROM sessions
		WHERE COALESCE(harness,'') != '' AND datetime(started_at) >= datetime(?)
		GROUP BY harness`, sinceArg(since))
}

// SessionsSeenByHarness counts named sessions seen at or after since at
// transcript or hook confidence, keyed by harness — whatever their start, so
// a conversation that began before since and is active now counts. An ended
// session counts only with an event since then: ending a session moves its
// last_seen_at to the end time, and a harness closing old conversations is no
// activity.
func (s *Store) SessionsSeenByHarness(since time.Time) map[string]int {
	at := sinceArg(since)
	return s.doctorCountByKey(`SELECT harness, COUNT(*) FROM sessions
		WHERE COALESCE(harness,'') != '' AND confidence IN (?, ?) AND datetime(last_seen_at) >= datetime(?)
		AND (status != ? OR EXISTS (SELECT 1 FROM events e WHERE e.session_id = sessions.id AND datetime(e.ts) >= datetime(?)))
		GROUP BY harness`, model.ConfTranscript, model.ConfHook, at, model.SessionEnded, at)
}

// RetentionReport lists every event kind present with its row and record
// counts, their budgets and how far back each cap keeps the kind, ordered by
// kind. Never nil.
func (s *Store) RetentionReport() []KindRetention {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []KindRetention{}
	rows, err := s.db.Query(`SELECT kind, COUNT(*), SUM(record) FROM events GROUP BY kind ORDER BY kind`)
	if err != nil {
		log.Printf("store: retention report error: %v", err)
		return out
	}
	for rows.Next() {
		var r KindRetention
		if rows.Scan(&r.Kind, &r.Rows, &r.RecordRows) != nil {
			continue
		}
		r.Name = event.Kind(r.Kind).String()
		r.Budget = kindBudget(r.Kind)
		r.Ring = ringKinds[r.Kind]
		r.RecordBudget = recordBudget
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: retention report: %v", err)
	}
	rows.Close()
	// The same seeks the prune runs: the budget-th newest row is the oldest
	// one the cap keeps.
	for i := range out {
		r := &out[i]
		r.HorizonTS = s.nthNewestTSLocked(`SELECT datetime(ts) FROM events WHERE kind = ? ORDER BY id DESC LIMIT 1 OFFSET ?`, r.Kind, r.Budget-1)
		r.RecordHorizonTS = s.nthNewestTSLocked(`SELECT datetime(ts) FROM events WHERE kind = ? AND record = 1 ORDER BY id DESC LIMIT 1 OFFSET ?`, r.Kind, r.RecordBudget-1)
	}
	return out
}

// nthNewestTSLocked runs a one-row timestamp query and returns it as RFC3339
// UTC, or "" when there is no such row. Caller holds mu.
func (s *Store) nthNewestTSLocked(q string, kind, offset int) string {
	var ts string
	if err := s.db.QueryRow(q, kind, offset).Scan(&ts); err != nil {
		return ""
	}
	t, err := time.Parse(time.DateTime, ts)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
