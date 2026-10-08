package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// A store whose idx_events_host an earlier build created on (remote_host, ts)
// gets it rebuilt, so the host list stops sorting.
func TestOpenRebuildsAnEarlierHostIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP INDEX idx_events_host`,
		`CREATE INDEX idx_events_host ON events(remote_host, ts) WHERE remote_host != ''`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var ddl string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = 'idx_events_host'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ddl, "remote_host, id, ts") {
		t.Fatalf("idx_events_host after reopen = %q, want (remote_host, id, ts)", ddl)
	}
	q, args := eventQuery(EventFilter{RemoteHost: "api.example.com", Limit: 50})
	if plan := queryPlan(t, s, q, args...); strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("host list plan after reopen = %q, want no sort", plan)
	}
}

// Host lookups seek idx_events_host instead of scanning every event, and the
// host filter reads newest first from the index without sorting the host's
// rows.
func TestHostLookupsUseTheHostIndex(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if plan := queryPlan(t, s, hostFirstSeenSQL, "api.example.com"); !strings.Contains(plan, "idx_events_host") {
		t.Errorf("host first-seen plan = %q, want idx_events_host", plan)
	}
	for _, f := range []EventFilter{
		{RemoteHost: "api.example.com", Limit: 50},
		{RemoteHost: "api.example.com", Since: "2026-10-01T00:00:00Z", Limit: 50},
	} {
		q, args := eventQuery(f)
		if plan := queryPlan(t, s, q, args...); !strings.Contains(plan, "idx_events_host") || strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("QueryEvents(%+v) plan = %q, want idx_events_host without a sort", f, plan)
		}
	}
}

// The host filter returns the same rows, newest first, and the trend's first
// sighting is the host's oldest event; events without a host never match.
func TestHostLookupsReturnTheHostsEvents(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	hosts := []string{"a.example", "", "b.example", "a.example", "", "a.example", "b.example"}
	for i, h := range hosts {
		s.PutEvent(event.Event{Kind: event.KindConnOpen, TS: base.Add(time.Duration(i) * time.Minute), PID: int32(i + 1), RemoteHost: h})
	}

	var pids []string
	for _, e := range s.QueryEvents(EventFilter{RemoteHost: "a.example", Limit: 50}) {
		pids = append(pids, fmt.Sprint(e.PID))
	}
	if got := strings.Join(pids, ","); got != "6,4,1" {
		t.Errorf("a.example events = %s, want 6,4,1", got)
	}
	if got := s.QueryEvents(EventFilter{RemoteHost: "a.example", Since: base.Add(2 * time.Minute).Format(time.RFC3339), Limit: 50}); len(got) != 2 {
		t.Errorf("a.example since +2m = %d events, want 2", len(got))
	}
	if got := s.QueryEvents(EventFilter{Limit: 50}); len(got) != len(hosts) {
		t.Errorf("unfiltered = %d events, want %d", len(got), len(hosts))
	}
	if tc := s.TrendFor("", "b.example"); !tc.HostKnown || tc.HostFirstSeen != base.Add(2*time.Minute).Format(time.RFC3339Nano) {
		t.Errorf("b.example trend = known %v first %q, want first %s", tc.HostKnown, tc.HostFirstSeen, base.Add(2*time.Minute).Format(time.RFC3339Nano))
	}
	if tc := s.TrendFor("", "c.example"); tc.HostKnown {
		t.Errorf("unseen host trend = %+v, want unknown", tc)
	}
}

// seedEventsWithHosts fills a fresh store with 300,000 events, 7% of them
// connections: half to hot.example, the rest spread over 500 hosts. The mix
// of a long-running daemon's store.
func seedEventsWithHosts(b *testing.B) *Store {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "e.db"), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 300000; i++ {
		kind, host := int(event.KindFileOpen), ""
		switch {
		case i%28 == 0:
			kind, host = int(event.KindConnOpen), "hot.example"
		case i%14 == 0:
			kind, host = int(event.KindConnOpen), fmt.Sprintf("h%d.example", (i/28)%500)
		}
		if _, err := tx.Exec(`INSERT INTO events (kind, ts, pid, exe_path, session_id, path, remote_host) VALUES (?, ?, ?, '/bin/x', 's', '/tmp/f', ?)`,
			kind, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano), i%400, host); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return s
}

func BenchmarkTrendForHost(b *testing.B) {
	s := seedEventsWithHosts(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.TrendFor("r", fmt.Sprintf("h%d.example", i%500))
	}
}

func BenchmarkQueryEventsByHost(b *testing.B) {
	s := seedEventsWithHosts(b)
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.QueryEvents(EventFilter{RemoteHost: fmt.Sprintf("h%d.example", i%500), Since: since, Limit: 50})
	}
}

func BenchmarkQueryEventsBusiestHost(b *testing.B) {
	s := seedEventsWithHosts(b)
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.QueryEvents(EventFilter{RemoteHost: "hot.example", Since: since, Limit: 50})
	}
}

func BenchmarkTrendForBusiestHost(b *testing.B) {
	s := seedEventsWithHosts(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.TrendFor("r", "hot.example")
	}
}

func BenchmarkPutConnEvent(b *testing.B) {
	s := seedEventsWithHosts(b)
	base := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.PutEvent(event.Event{Kind: event.KindConnOpen, TS: base.Add(time.Duration(i) * time.Millisecond), PID: int32(i % 400),
			RemoteHost: fmt.Sprintf("h%d.example", i%500), RemotePort: 443})
	}
}
