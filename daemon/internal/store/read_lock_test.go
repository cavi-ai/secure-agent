package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Flag and event reads never wait for the store's write lock, so a long
// write or retention statement does not stall the console's reads, and a
// long read does not stall event persistence.
func TestReadsDoNotWaitForTheWriteLock(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 2, PID: 1, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdvisorVerdict("f1", "flag", model.AdvisorVerdict{Rationale: "seen", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutEvent(event.Event{Kind: event.KindExec, PID: 1, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	reads := map[string]func() error{
		"flags": func() error {
			flags, err := s.QueryFlags(FlagFilter{Limit: 10})
			if err == nil && (len(flags) != 1 || flags[0].Advisor == nil) {
				t.Errorf("flags read: %+v", flags)
			}
			return err
		},
		"flag with advice": func() error {
			if f, ok := s.GetFlagWithAdvisor("f1"); !ok || f.Advisor == nil {
				t.Errorf("flag with advice: %+v %v", f, ok)
			}
			return nil
		},
		"verdicts": func() error { _, err := s.AdvisorVerdictsFor([]string{"f1"}, "flag"); return err },
		"events":   func() error { _, err := s.QueryEvents(EventFilter{Limit: 10}); return err },
		"event pages": func() error {
			_, _, err := s.QueryRecordedEvents(EventFilter{Limit: 10}, 0)
			return err
		},
	}
	done := make(chan string, len(reads))
	for name, read := range reads {
		go func() {
			if err := read(); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			done <- name
		}()
	}
	for range reads {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("a read waited for the write lock")
		}
	}
}
