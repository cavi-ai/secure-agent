package daemon

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// seedEventRows fills the events table through its own connection with the
// per-kind rows of a long-running daemon at its retention budgets, so each
// benchmarked insert pays its index costs and file opens churn at budget.
func seedEventRows(b *testing.B, path string) {
	b.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(3000)")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	// Rows from the last 20 minutes: inside every time retention, so a pass
	// trims only what is over budget, as on a live daemon.
	base := time.Now().Add(-20 * time.Minute)
	i := 0
	for _, seed := range []struct {
		kind event.Kind
		rows int
	}{
		{event.KindFileOpen, 40000}, {event.KindFileWrite, 150000}, {event.KindModelCall, 70000},
		{event.KindToolCall, 50000}, {event.KindConnOpen, 30000}, {event.KindConnClose, 30000},
	} {
		for n := 0; n < seed.rows; n, i = n+1, i+1 {
			if _, err := tx.Exec(`INSERT INTO events (kind, ts, pid, exe_path, session_id, path) VALUES (?, ?, ?, '/usr/local/bin/agent', ?, ?)`,
				int(seed.kind), base.Add(time.Duration(i)*3*time.Millisecond).UTC().Format(time.RFC3339Nano), i%400,
				fmt.Sprintf("s%d", i%200), fmt.Sprintf("/w/repo%d/f%d.go", i%50, i%5000)); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkIngestAgentFileOpens feeds an agent's file opens through the ingest
// loop into an on-disk store seeded like a long-running daemon's: the load
// file telemetry puts on the daemon.
func BenchmarkIngestAgentFileOpens(b *testing.B) {
	path := filepath.Join(b.TempDir(), "events.db")
	st, err := store.Open(path, "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	seedEventRows(b, path)
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		b.Fatal(err)
	}
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg, correlate.Hooks{})
	input := make(chan event.Event, 2048)
	ingest := runEventIngest(input, ingestDeps{Store: st, Correlator: cr, Resolver: session.NewResolver(st, tagger), Tagger: tagger})
	base := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Each file is opened 12/7 times, the measured share of a live
		// daemon's stored opens that repeat a process's open of the file.
		input <- event.Event{Kind: event.KindFileOpen, TS: base.Add(time.Duration(i) * time.Microsecond), PID: 500,
			ExePath: "/usr/local/bin/cursor-agent", Path: fmt.Sprintf("/w/repo/src/f%d.go", i*7/12)}
	}
	close(input)
	<-ingest.Done()
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}
