package daemon

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Repeats within the window fold into the stored row: a process's opens of
// one file without a session, a session's opens of one file and its execs of
// one tool from one image. Another process, session, file, tool or image, a
// write, or activity after the window is stored.
func TestRepeatActivityFoldsWithinTheWindow(t *testing.T) {
	r := repeatActivity{window: time.Minute}
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	open := func(pid int32, path string, at time.Duration) event.Event {
		return event.Event{Kind: event.KindFileOpen, PID: pid, Path: path, TS: t0.Add(at)}
	}
	stored := func(e event.Event) bool {
		if r.seen(e) {
			return false
		}
		r.remember(e)
		return true
	}
	for _, step := range []struct {
		e      event.Event
		stored bool
		why    string
	}{
		{open(7, "/w/a", 0), true, "first open"},
		{open(7, "/w/a", 30*time.Second), false, "repeat within the window"},
		{open(8, "/w/a", 31*time.Second), true, "another process"},
		{open(7, "/w/b", 32*time.Second), true, "another file"},
		{open(7, "/w/a", 90*time.Second), false, "repeat in the next window"},
		{open(7, "/w/a", 200*time.Second), true, "after the window"},
		{event.Event{Kind: event.KindFileWrite, PID: 7, Path: "/w/b", TS: t0.Add(201 * time.Second)}, true, "writes are not folded"},
		{event.Event{Kind: event.KindFileWrite, PID: 7, Path: "/w/b", TS: t0.Add(202 * time.Second)}, true, "writes are not folded"},
		{event.Event{Kind: event.KindFileOpen, PID: 20, SessionID: "s", Path: "/w/c", TS: t0.Add(203 * time.Second)}, true, "a session's first open"},
		{event.Event{Kind: event.KindFileOpen, PID: 21, SessionID: "s", Path: "/w/c", TS: t0.Add(204 * time.Second)}, false, "another process of the session"},
		{event.Event{Kind: event.KindFileOpen, PID: 21, SessionID: "t", Path: "/w/c", TS: t0.Add(205 * time.Second)}, true, "another session"},
		{event.Event{Kind: event.KindExec, PID: 30, SessionID: "s", ExePath: "/bin/bash", Path: "/usr/bin/sed", TS: t0.Add(206 * time.Second)}, true, "a session's first exec"},
		{event.Event{Kind: event.KindExec, PID: 31, SessionID: "s", ExePath: "/bin/bash", Path: "/usr/bin/sed", TS: t0.Add(207 * time.Second)}, false, "the same tool again"},
		{event.Event{Kind: event.KindExec, PID: 32, SessionID: "s", ExePath: "/bin/zsh", Path: "/usr/bin/sed", TS: t0.Add(208 * time.Second)}, true, "the tool from another image"},
		{event.Event{Kind: event.KindExec, PID: 33, SessionID: "s", ExePath: "/bin/bash", Path: "/usr/bin/curl", TS: t0.Add(209 * time.Second)}, true, "another tool"},
		{event.Event{Kind: event.KindFileOpen, PID: 34, SessionID: "s", Path: "/usr/bin/sed", TS: t0.Add(210 * time.Second)}, true, "an open of an executed file"},
	} {
		if got := stored(step.e); got != step.stored {
			t.Fatalf("%s: stored %v, want %v", step.why, got, step.stored)
		}
	}
}

// Only a stored open is remembered: after a failed write the next open of
// the file is stored.
func TestRepeatOpenWithoutAStoredRowIsStored(t *testing.T) {
	r := repeatActivity{window: time.Minute}
	e := event.Event{Kind: event.KindFileOpen, PID: 7, Path: "/w/a", TS: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	if r.seen(e) {
		t.Fatal("first open read as a repeat")
	}
	e.TS = e.TS.Add(time.Second)
	if r.seen(e) {
		t.Fatal("an open whose write failed folded the next one")
	}
}

// An agent process's repeated opens of one file are stored once.
func TestDrainStoresARepeatedOpenOnce(t *testing.T) {
	f := newPersistenceFixture(t)
	t0 := time.Now().UTC()
	open := func(path string, at time.Duration) event.Event {
		return event.Event{Kind: event.KindFileOpen, PID: 500, ExePath: "/usr/local/bin/cursor-agent", Path: path, TS: t0.Add(at)}
	}
	f.drain(t, open("/w/repo/a.go", 0), open("/w/repo/a.go", time.Second), open("/w/repo/b.go", time.Second), open("/w/repo/a.go", 2*time.Second))
	for path, want := range map[string]int{"/w/repo/a.go": 1, "/w/repo/b.go": 1} {
		var n int
		if err := f.db.QueryRow(`SELECT COUNT(*) FROM events WHERE path=?`, path).Scan(&n); err != nil || n != want {
			t.Fatalf("%s: %d rows, %v; want %d", path, n, err, want)
		}
	}
}
