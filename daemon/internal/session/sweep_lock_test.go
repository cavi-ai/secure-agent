package session

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// stallingStore parks one read until released.
type stallingStore struct {
	*store.Store
	method           string
	entered, release chan struct{}
}

func (s *stallingStore) stall(method string) {
	if s.method == method {
		s.method = ""
		close(s.entered)
		<-s.release
	}
}

func (s *stallingStore) SessionRoots() map[int32][]model.Session {
	s.stall("SessionRoots")
	return s.Store.SessionRoots()
}

func (s *stallingStore) ListSessions(f store.SessionFilter) ([]model.Session, error) {
	s.stall("ListSessions")
	return s.Store.ListSessions(f)
}

// Event attribution does not wait for Sweep's store reads.
func TestSweepStoreReadsDoNotBlockResolve(t *testing.T) {
	for _, method := range []string{"SessionRoots", "ListSessions"} {
		t.Run(method, func(t *testing.T) {
			st, err := store.Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			cfg, _ := config.Load("/nonexistent")
			tg := agents.New(cfg, fakeProcs{100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: time.Now().Add(-time.Hour)}})
			tg.Refresh()
			stall := &stallingStore{Store: st, method: method, entered: make(chan struct{}), release: make(chan struct{})}
			r := NewResolver(stall, tg)

			swept := make(chan struct{})
			go func() { r.Sweep(); close(swept) }()
			<-stall.entered
			resolved := make(chan string, 1)
			go func() {
				e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
				resolved <- r.Resolve(&e)
			}()
			select {
			case id := <-resolved:
				if id == "" {
					t.Fatal("event not attributed")
				}
			case <-time.After(2 * time.Second):
				close(stall.release)
				<-swept
				t.Fatalf("Resolve waited for Sweep's %s", method)
			}
			close(stall.release)
			<-swept
		})
	}
}
