package session

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
)

// A session whose root exited while the daemon was down ends at its last
// activity, not at the sweep that found the root gone: last_seen_at keeps
// the last thing observed, so a days-old session is not listed as just seen.
func TestSweepEndsSilentSessionAtItsLastActivity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	procs := fakeProcs{200: {PID: 200, PPID: 1, Exe: "/usr/local/bin/codex", CWD: "/repo", StartTime: time.Now().Add(-time.Hour).Truncate(time.Second)}}
	cfg, _ := config.Load("/nonexistent")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	tagger := agents.New(cfg, procs)
	tagger.Refresh()
	r := NewResolver(st, tagger)
	ev := event.Event{Kind: event.KindFileOpen, PID: 200, TS: time.Now()}
	id := r.Resolve(&ev)
	if id == "" {
		t.Fatal("process was not attributed")
	}
	before, ok := testutil.Lookup[model.Session](t)(st.GetSession(id))
	if !ok {
		t.Fatal("session not stored")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// The root exits while the daemon is down; it starts again four days on.
	delete(procs, 200)
	st, err = store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tagger = agents.New(cfg, procs)
	tagger.Refresh()
	r = NewResolver(st, tagger)
	later := time.Now().Add(96 * time.Hour)
	r.now = func() time.Time { return later }
	r.Sweep()

	got, ok := testutil.Lookup[model.Session](t)(st.GetSession(id))
	if !ok || got.Status != model.SessionEnded {
		t.Fatalf("session = %+v, found=%v; want ended", got, ok)
	}
	if !got.LastSeenAt.Equal(before.LastSeenAt) {
		t.Errorf("last_seen_at = %v, want the last activity %v", got.LastSeenAt, before.LastSeenAt)
	}
	if got.EndedAt == nil || !got.EndedAt.Equal(before.LastSeenAt) {
		t.Errorf("ended_at = %v, want the last activity %v", got.EndedAt, before.LastSeenAt)
	}
}
