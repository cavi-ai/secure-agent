package daemon

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
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

// buildProcs is an agent (pid 500) whose build runs short-lived children.
type buildProcs struct{ children int32 }

const buildChildBase = 10000

func (b buildProcs) List() []agents.ProcInfo {
	out := []agents.ProcInfo{{PID: 500, PPID: 1, Exe: "/usr/local/bin/cursor-agent"}}
	for k := int32(0); k < b.children; k++ {
		out = append(out, agents.ProcInfo{PID: buildChildBase + k, PPID: 500, Exe: "/bin/bash"})
	}
	return out
}

func (b buildProcs) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 500 {
		return agents.ProcInfo{PID: 500, PPID: 1, Exe: "/usr/local/bin/cursor-agent"}, true
	}
	if pid >= buildChildBase && pid < buildChildBase+b.children {
		return agents.ProcInfo{PID: pid, PPID: 500, Exe: "/bin/bash"}, true
	}
	return agents.ProcInfo{}, false
}

// A build under an agent forks a shell per step: each child execs the same
// tool and opens the same sources. The store keeps one row per file and per
// tool for the session, and the WAL grows by a bounded amount per event.
func TestBuildLoadStoresSessionActivityOnceAndWritesLittle(t *testing.T) {
	const children, files = 200, 40
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tagger := agents.New(cfg, buildProcs{children: children})
	tagger.Refresh()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := persistenceFixture{store: st, db: db, tagger: tagger, cfg: cfg}

	// A reader holding its snapshot keeps every WAL frame in the file, so the
	// WAL's size is the bytes the run wrote to it.
	reader, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := reader.QueryRow(`SELECT count(*) FROM events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	walBefore := fileSize(t, path+"-wal")

	at := time.Now().UTC()
	var input []event.Event
	for k := int32(0); k < children; k++ {
		pid := buildChildBase + k
		ts := at.Add(time.Duration(k) * 100 * time.Millisecond)
		input = append(input, event.Event{Kind: event.KindExec, TS: ts, PID: pid, PPID: 500, ExePath: "/bin/bash", Path: "/usr/bin/sed"})
		for j := 0; j < files; j++ {
			input = append(input, event.Event{Kind: event.KindFileOpen, TS: ts, PID: pid, PPID: 500, ExePath: "/usr/bin/sed", Path: "/work/src/f" + strconv.Itoa(j) + ".h"})
		}
	}
	feedAll(t, f, input)

	walBytes := fileSize(t, path+"-wal") - walBefore
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	counts := map[int]int{}
	rows, err := f.db.Query(`SELECT kind, count(*) FROM events GROUP BY kind`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var kind, c int
		if err := rows.Scan(&kind, &c); err != nil {
			t.Fatal(err)
		}
		counts[kind] = c
	}
	rows.Close()
	perEvent := walBytes / int64(len(input))
	t.Logf("events in %d, stored opens %d execs %d, WAL %d bytes (%d per event)", len(input), counts[int(event.KindFileOpen)], counts[int(event.KindExec)], walBytes, perEvent)
	if got := counts[int(event.KindFileOpen)]; got != files {
		t.Errorf("stored %d opens, want one per file (%d)", got, files)
	}
	if got := counts[int(event.KindExec)]; got != 1 {
		t.Errorf("stored %d execs, want one per tool (1)", got)
	}
	if perEvent > 256 {
		t.Errorf("WAL grew %d bytes per event, want at most 256", perEvent)
	}
}

func feedAll(t *testing.T, f persistenceFixture, events []event.Event) {
	t.Helper()
	input := make(chan event.Event, len(events))
	for _, e := range events {
		input <- e
	}
	close(input)
	cr := correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{})
	done := runEventIngest(input, ingestDeps{Store: f.store, Correlator: cr, Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger,
		RecordEgressObservation: f.store.RecordEgressObservationForTest}).Done()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("drain did not finish")
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}
