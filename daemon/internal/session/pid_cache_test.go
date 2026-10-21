package session

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Sweep drops a cached pid another process now holds at once, and an exited
// pid once its late events have had pidGoneGrace to arrive.
func TestSweepDropsReusedAndLongGonePIDs(t *testing.T) {
	now := time.Now()
	r, _ := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: now.Add(-time.Hour)},
		101: {PID: 101, PPID: 1, Exe: "/bin/zsh", CWD: "/tmp", StartTime: now.Add(-time.Minute)},
	})
	r.now = func() time.Time { return now }
	r.byPID[100] = pidEntry{id: "s", started: now.Add(-time.Hour)}     // same process
	r.byPID[101] = pidEntry{id: "s", started: now.Add(-2 * time.Hour)} // pid reused
	r.byPID[102] = pidEntry{id: "s", started: now.Add(-time.Hour)}     // exited

	r.Sweep()
	if _, ok := r.byPID[101]; ok {
		t.Fatal("pid held by another process still resolves to the old session")
	}
	if ent, ok := r.byPID[102]; !ok || ent.goneAt.IsZero() {
		t.Fatalf("exited pid = %+v, %v; want kept for its late events", ent, ok)
	}
	e := event.Event{Kind: event.KindFileOpen, PID: 102, TS: now}
	if id := r.Resolve(&e); id != "s" {
		t.Fatalf("late event of an exited pid resolved to %q, want s", id)
	}

	r.now = func() time.Time { return now.Add(pidGoneGrace + time.Second) }
	r.Sweep()
	if _, ok := r.byPID[102]; ok {
		t.Fatal("pid gone past the grace window still cached")
	}
	if _, ok := r.byPID[100]; !ok {
		t.Fatal("live pid dropped")
	}
}

// A cached pid records the start of the process that held it.
func TestCachedPIDRecordsProcessStart(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	r, _ := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: started},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	id := r.Resolve(&e)
	if ent := r.byPID[100]; ent.id != id || !ent.started.Equal(started) {
		t.Fatalf("byPID[100] = %+v, want %q started %v", ent, id, started)
	}
}
