package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// sessionBound is the documented number of session records one node keeps.
const sessionBound = 512

func sessionID(i int) string { return fmt.Sprintf("s%04d", i) }

func sessionStamp(i int) string {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339)
}

// idRange returns the session ids for indexes from through to-1, sorted.
func idRange(from, to int) []string {
	ids := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		ids = append(ids, sessionID(i))
	}
	return ids
}

func appendSession(t *testing.T, s *Store, node string, i int, status string) {
	t.Helper()
	payload, err := json.Marshal(sessionPayload{ID: sessionID(i), Status: status, LastSeenAt: sessionStamp(i)})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, Envelope{NodeID: node, Kind: "session", Payload: payload})
}

func appendTrace(t *testing.T, s *Store, node, session string, i int) {
	t.Helper()
	payload, err := json.Marshal(tracePayload{SessionID: session, TS: sessionStamp(i), Tool: "Bash"})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, Envelope{NodeID: node, Kind: "trace", Payload: payload})
}

func assertIDs(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d ids, want %d", what, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: id %d = %q, want %q", what, i, got[i], want[i])
		}
	}
}

// assertNodeSessions checks the sorted ids that Sessions() serves for node.
func assertNodeSessions(t *testing.T, s *Store, node string, want []string) {
	t.Helper()
	var got []string
	for _, sess := range s.Sessions() {
		if sess.NodeID == node {
			got = append(got, sess.ID)
		}
	}
	slices.Sort(got)
	assertIDs(t, "sessions for "+node, got, want)
}

// writtenCheckpoint saves the store's checkpoint for node into a new
// directory and decodes the file read back from it.
func writtenCheckpoint(t *testing.T, s *Store, node string) nodeCheckpoint {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := s.saveCheckpoint(root, node, 1); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, node+checkpointSuffix))
	if err != nil {
		t.Fatal(err)
	}
	var cp rollupCheckpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		t.Fatal(err)
	}
	return cp.Nodes[node]
}

func TestSessionBoundKeepsNewestEndedSessions(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir)
	const extra = 10
	for i := 0; i < sessionBound+extra; i++ {
		appendSession(t, s, "n1", i, "ended")
	}
	appendSession(t, s, "n2", 0, "ended")

	want := idRange(extra, sessionBound+extra)
	assertNodeSessions(t, s, "n1", want)
	assertNodeSessions(t, s, "n2", idRange(0, 1))

	// Replay at startup applies the same bound.
	s = openTestStore(t, dir)
	assertNodeSessions(t, s, "n1", want)
}

func TestSessionBoundEvictsEndedBeforeLive(t *testing.T) {
	s := openTestStore(t, t.TempDir())
	const live = 100
	for i := 0; i < live; i++ {
		appendSession(t, s, "n1", i, "active")
	}
	for i := live; i < live+sessionBound; i++ {
		appendSession(t, s, "n1", i, "ended")
	}
	// The 100 oldest ended sessions go; every live session stays, though older.
	assertNodeSessions(t, s, "n1", append(idRange(0, live), idRange(2*live, live+sessionBound)...))
}

func TestSessionBoundEvictsOldestLiveSessions(t *testing.T) {
	s := openTestStore(t, t.TempDir())
	const extra = 8
	for i := 1; i <= sessionBound+extra; i++ {
		appendSession(t, s, "n1", i, "active")
	}
	assertNodeSessions(t, s, "n1", idRange(extra+1, sessionBound+extra+1))

	// The incoming record stays even when it orders first for eviction.
	appendSession(t, s, "n1", 0, "ended")
	assertNodeSessions(t, s, "n1", append(idRange(0, 1), idRange(extra+2, sessionBound+extra+1)...))
}

func TestSessionBoundEvictsByInstant(t *testing.T) {
	const oldest = "2026-01-01T00:00:00Z"
	const newer = "2026-01-01T00:00:00.1Z"
	t.Run("sessions", func(t *testing.T) {
		rt := nodeRuntime{sessions: make(map[string]sessionPayload, sessionBound+1)}
		rt.sessions["oldest"] = sessionPayload{LastSeenAt: oldest}
		rt.sessions["newer"] = sessionPayload{LastSeenAt: newer}
		for i := 1; i < sessionBound; i++ {
			rt.sessions[sessionID(i)] = sessionPayload{LastSeenAt: sessionStamp(i)}
		}
		rt.boundSessions(sessionID(sessionBound - 1))
		_, keptOldest := rt.sessions["oldest"]
		_, keptNewer := rt.sessions["newer"]
		if keptOldest || !keptNewer {
			t.Fatalf("retained oldest=%t, newer=%t; want oldest evicted and newer retained", keptOldest, keptNewer)
		}
	})
	t.Run("traces", func(t *testing.T) {
		rt := nodeRuntime{lastTrace: make(map[string]tracePayload, sessionBound+1)}
		rt.lastTrace["oldest"] = tracePayload{TS: oldest}
		rt.lastTrace["newer"] = tracePayload{TS: newer}
		for i := 1; i < sessionBound; i++ {
			rt.lastTrace[sessionID(i)] = tracePayload{TS: sessionStamp(i)}
		}
		rt.boundTraces()
		_, keptOldest := rt.lastTrace["oldest"]
		_, keptNewer := rt.lastTrace["newer"]
		if keptOldest || !keptNewer {
			t.Fatalf("retained oldest=%t, newer=%t; want oldest evicted and newer retained", keptOldest, keptNewer)
		}
	})
}

func TestSessionBoundCheckpointHoldsOnlyKeptSessionsAndTraces(t *testing.T) {
	s := openTestStore(t, t.TempDir())
	const extra = 20
	for i := 0; i < sessionBound+extra; i++ {
		appendSession(t, s, "n1", i, "ended")
		appendTrace(t, s, "n1", sessionID(i), i)
	}
	// Traces without a session record are dropped while the trace map is full.
	for i := 0; i < extra; i++ {
		appendTrace(t, s, "n1", fmt.Sprintf("orphan-%02d", i), sessionBound+extra+i)
	}

	cp := writtenCheckpoint(t, s, "n1")
	want := idRange(extra, sessionBound+extra)
	assertIDs(t, "checkpoint sessions", slices.Sorted(maps.Keys(cp.Sessions)), want)
	assertIDs(t, "checkpoint traces", slices.Sorted(maps.Keys(cp.LastTrace)), want)
}

func TestSessionBoundTrimsOversizedCheckpointOnLoad(t *testing.T) {
	dir := t.TempDir()
	const live, ended = 300, 300
	node := nodeCheckpoint{
		State:     &NodeState{NodeID: "n1"},
		Sessions:  map[string]sessionPayload{},
		LastTrace: map[string]tracePayload{"orphan": {SessionID: "orphan", TS: sessionStamp(live + ended)}},
	}
	for i := 0; i < live+ended; i++ {
		status := "active"
		if i >= live {
			status = "ended"
		}
		node.Sessions[sessionID(i)] = sessionPayload{ID: sessionID(i), Status: status, LastSeenAt: sessionStamp(i)}
		node.LastTrace[sessionID(i)] = tracePayload{SessionID: sessionID(i), TS: sessionStamp(i)}
	}
	b, err := json.Marshal(rollupCheckpoint{Through: 1, Nodes: map[string]nodeCheckpoint{"n1": node}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "n1"+checkpointSuffix), b, 0o600); err != nil {
		t.Fatal(err)
	}

	s := openTestStore(t, dir)
	// The 88 oldest ended sessions go first, though every live session is older.
	want := append(idRange(0, live), idRange(live+ended-(sessionBound-live), live+ended)...)
	assertNodeSessions(t, s, "n1", want)
	cp := writtenCheckpoint(t, s, "n1")
	assertIDs(t, "checkpoint sessions", slices.Sorted(maps.Keys(cp.Sessions)), want)
	assertIDs(t, "checkpoint traces", slices.Sorted(maps.Keys(cp.LastTrace)), want)
}
