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

func TestReopenedStoreRejectsReusedRootProcess(t *testing.T) {
	for _, sameLifetime := range []bool{false, true} {
		t.Run(map[bool]string{false: "reused", true: "same-lifetime"}[sameLifetime], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sessions.db")
			started := time.Now().Add(-time.Hour).Truncate(time.Second)
			current := started
			if !sameLifetime {
				current = started.Add(time.Minute)
			}
			procs := fakeProcs{200: {PID: 200, PPID: 1, Exe: "/usr/local/bin/codex", CWD: "/repo", StartTime: started}}
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			cfg, _ := config.Load("/nonexistent")
			tagger := agents.New(cfg, procs)
			tagger.Refresh()
			r := NewResolver(st, tagger)
			first := event.Event{Kind: event.KindFileOpen, PID: 200, TS: time.Now()}
			id := r.Resolve(&first)
			if id == "" {
				t.Fatal("initial process was not attributed")
			}
			if !sameLifetime {
				if err := st.EndSession(id, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}

			procs[200] = agents.ProcInfo{PID: 200, PPID: 1, Exe: "/usr/local/bin/codex", CWD: "/repo", StartTime: current}
			st, err = store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			tagger = agents.New(cfg, procs)
			tagger.Refresh()
			r = NewResolver(st, tagger)
			next := event.Event{Kind: event.KindExec, PID: 200, TS: time.Now()}
			got := r.Resolve(&next)
			if sameLifetime {
				if got != id {
					t.Fatalf("same process lifetime resolved to %q, want %q", got, id)
				}
				return
			}
			if got == id || got == "" {
				t.Fatalf("reused root resolved to old/empty session %q", got)
			}
			old, ok := testutil.Lookup[model.Session](t)(st.GetSession(id))
			if !ok || old.Status != model.SessionEnded {
				t.Fatalf("old session = %+v, found=%v; want ended", old, ok)
			}
			if next.SessionID != got {
				t.Fatalf("new activity session=%q, resolved=%q", next.SessionID, got)
			}
		})
	}
}
