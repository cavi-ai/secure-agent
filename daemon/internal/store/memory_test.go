package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

func TestSessionMemorySources(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Second)
	root := now.Add(-time.Minute)
	s.UpsertSession(model.Session{ID: "s1", RootPID: 100, RootStartedAt: root.Format(time.RFC3339Nano), StartedAt: root, LastSeenAt: now})
	s.UpsertSession(model.Session{ID: "other", StartedAt: root, LastSeenAt: now})
	at := now.Format(time.RFC3339Nano)
	for _, q := range []string{
		`INSERT INTO events(kind,ts,session_id) VALUES (8,'` + at + `','s1')`,
		`INSERT INTO events(kind,ts,session_id) VALUES (8,'` + at + `','other')`,
		`INSERT INTO flags(id,rule,severity,ts,session_id) VALUES ('f1','keychain-access',3,'` + at + `','s1')`,
		`INSERT INTO incidents(id,rule,risk,created_at,status,session_id,aggregate_count) VALUES ('i1','keychain-access','high','` + at + `','resolved','s1',2)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s.PutGuardDecisionForTest(GuardDecision{ID: "g1", SessionID: "s1", RuleID: "cloud-creds", Verdict: "deny", Scope: "once", At: at})
	episode := resource.Episode{CapturedAt: now, Severity: "warning", DiagnosisCodes: []string{"heavy-memory"}, Session: resource.Session{Key: fmt.Sprintf("100:%d", root.UnixNano()), RootPID: 100, RootStartedAt: root, RSSBytes: 4 << 30}}
	if err := s.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	// An older episode has no session_id. Its exact family key is eligible.
	if _, err := s.db.Exec(`INSERT INTO resource_episodes(captured_at,severity,session_key,episode_json) VALUES (?,?,?,?)`, at, "warning", episode.Session.Key, `{"session":{"kind":"agent","rss_bytes":42},"diagnosis_codes":["heavy-memory"]}`); err != nil {
		t.Fatal(err)
	}
	facts, _, err := s.QuerySessionMemory("s1", nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range facts {
		counts[f.Kind]++
		if f.SessionID != "s1" {
			t.Fatalf("foreign fact %+v", f)
		}
		if f.Kind == "incident" && (f.Status != "resolved" || !f.At.Equal(now)) {
			t.Fatalf("resolved incident %+v", f)
		}
	}
	for kind, want := range map[string]int{"activity": 1, "flag": 1, "incident": 1, "guard": 1, "resource": 2} {
		if counts[kind] != want {
			t.Fatalf("counts=%v; %s want %d", counts, kind, want)
		}
	}
	if got := s.SessionIDForFamilyKey(fmt.Sprintf("100:%d", root.Add(time.Nanosecond).UnixNano())); got != "" {
		t.Fatalf("inexact legacy family resolved %q", got)
	}
}

func TestSessionMemoryCursor(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 510; i++ {
		if _, err := tx.Exec(`INSERT INTO events(kind,ts,session_id) VALUES (?,?,?)`, 8, at, "s1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	first, earlier, err := s.QuerySessionMemory("s1", nil, 0)
	if err != nil || len(first) != 200 || !earlier {
		t.Fatalf("default page=%d earlier=%v err=%v", len(first), earlier, err)
	}
	large, _, err := s.QuerySessionMemory("s1", nil, 900)
	if err != nil || len(large) != 500 {
		t.Fatalf("capped page=%d err=%v", len(large), err)
	}
	cursor := MemoryCursor{At: first[0].At, SourceRank: first[0].SourceRank, SourceID: first[0].SourceID}
	second, more, err := s.QuerySessionMemory("s1", &cursor, 200)
	if err != nil || len(second) != 200 || !more {
		t.Fatalf("second page=%d more=%v err=%v", len(second), more, err)
	}
	seen := map[string]bool{}
	for _, f := range first {
		seen[f.ID] = true
	}
	for _, f := range second {
		if seen[f.ID] {
			t.Fatalf("duplicate %s", f.ID)
		}
		seen[f.ID] = true
	}
	if !first[0].At.Equal(second[0].At) || first[0].SourceID <= second[len(second)-1].SourceID {
		t.Fatalf("same-time ordering failed: first=%+v second=%+v", first[0], second[len(second)-1])
	}
}

func TestSessionMemoryCursorAcrossSourceRanks(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339Nano)
	for _, q := range []string{
		`INSERT INTO events(kind,ts,session_id) VALUES (8,'` + at + `','s1')`,
		`INSERT INTO flags(id,rule,severity,ts,session_id) VALUES ('flag','keychain-access',3,'` + at + `','s1')`,
		`INSERT INTO guard_decisions(id,session_id,rule_id,verdict,scope,at) VALUES ('guard','s1','cloud-creds','deny','once','` + at + `')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var before *MemoryCursor
	for i, want := range []int{memoryGuardRank, memoryFlagRank, memoryActivityRank} {
		facts, earlier, err := s.QuerySessionMemory("s1", before, 1)
		if err != nil || len(facts) != 1 || facts[0].SourceRank != want || earlier != (i < 2) {
			t.Fatalf("page %d: facts=%+v earlier=%v err=%v", i, facts, earlier, err)
		}
		before = &MemoryCursor{At: facts[0].At, SourceRank: facts[0].SourceRank, SourceID: facts[0].SourceID}
	}
}

func TestSessionMemoryGuardRetentionAtRead(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetEventRetention(time.Hour, time.Hour)
	old := time.Now().Add(-2 * time.Hour).UTC().Format(guardDecisionTimeLayout)
	if _, err := s.db.Exec(`INSERT INTO guard_decisions(id,session_id,rule_id,verdict,scope,at) VALUES ('expired','s1','r','deny','once',?)`, old); err != nil {
		t.Fatal(err)
	}
	facts, _, err := s.QuerySessionMemory("s1", nil, 10)
	if err != nil || len(facts) != 0 {
		t.Fatalf("expired guard visible: %+v err=%v", facts, err)
	}
}

func TestSessionMemoryFractionalTimestampOrder(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, at := range []string{"2026-09-26T12:00:00.9Z", "2026-09-26T12:00:00.12Z", "2026-09-26T12:00:00.999999999Z"} {
		if _, err := s.db.Exec(`INSERT INTO events(kind,ts,session_id) VALUES (8,?,'s1')`, at); err != nil {
			t.Fatal(err)
		}
	}
	facts, earlier, err := s.QuerySessionMemory("s1", nil, 2)
	if err != nil || !earlier || len(facts) != 2 {
		t.Fatalf("page=%+v earlier=%v err=%v", facts, earlier, err)
	}
	if facts[0].At.Nanosecond() != 900000000 || facts[1].At.Nanosecond() != 999999999 {
		t.Fatalf("fractional ordering: %+v", facts)
	}
}

func TestSessionMemoryUsesTimeIndex(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	expr := memoryTimestampExpr("ts")
	rows, err := s.db.Query("EXPLAIN QUERY PLAN SELECT CAST(id AS TEXT) FROM events WHERE session_id = ? ORDER BY "+expr+" DESC, CAST(id AS TEXT) DESC LIMIT ?", "s1", 201)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail + "\n"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "idx_memory_events") {
		t.Fatalf("memory query does not use timestamp index: %s", plan)
	}
}
