package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"testing"
	"time"
)

func TestCoverageKeepsLastKnownActivityOnReadFailure(t *testing.T) {
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertSession(model.Session{ID: "s", Harness: "claude", StartedAt: time.Now()})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: time.Now(), SessionID: "s", CallID: "a"})
	a := New(Deps{Store: st, Status: func() Status { return Status{} }})
	before := a.recentHarnessActivity()["claude"].TraceLastSeen
	if before == "" {
		t.Fatal("fixture has no activity")
	}
	st.Close()
	a.harnessActivity.at = time.Time{}
	after := a.recentHarnessActivity()["claude"].TraceLastSeen
	if after != before {
		t.Fatal("read failure erased last known evidence")
	}
	if state, _ := checkStorage(doctorFacts{st: a.evidenceStatus(Status{})}); state != doctorFail {
		t.Fatal("failed activity read invisible in Doctor")
	}
}
