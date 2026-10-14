package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

func TestHostReportOrderingFreshnessAndBounds(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.TrackHookIngestion()
	now := time.Now().UTC()
	r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 1, Harness: "codex", ForwarderID: "instance-1", Sequence: 1, TS: now, State: "error", Pending: 2, DeliveryFailures: 1}
	s.noteHookForwarder(r, now)
	s.noteHookForwarder(r, now.Add(3*time.Minute)) // retry must not refresh receipt
	h := s.hookIngestionAt(now.Add(3 * time.Minute))
	if len(h.Forwarders) != 1 || h.Forwarders[0].Freshness != "stale" || !h.Forwarders[0].ReceivedAt.Equal(now) {
		t.Fatalf("stale duplicate: %+v", h)
	}
	r.Sequence++
	r.TS = now.Add(3 * time.Minute)
	r.State = "connected"
	r.Pending = 0
	s.noteHookForwarder(r, r.TS)
	h = s.hookIngestionAt(r.TS)
	if h.Forwarders[0].Freshness != "recent" || h.Forwarders[0].Report.State != "connected" {
		t.Fatalf("recovery: %+v", h)
	}
	r.Sequence++
	r.DeliveryFailures = 0 // cumulative counters cannot regress
	s.noteHookForwarder(r, r.TS)
	if s.HookIngestion().Rejected != 1 {
		t.Fatal("counter reset accepted without new instance identity")
	}
	r.DeliveryFailures = 1
	r.TS = now.Add(10 * time.Minute)
	s.noteHookForwarder(r, now.Add(4*time.Minute))
	if h = s.hookIngestionAt(now.Add(4 * time.Minute)); h.Forwarders[0].Freshness != "unverified" {
		t.Fatalf("future report=%+v", h)
	}
	for i := 0; i < 130; i++ {
		r.ForwarderID = fmt.Sprintf("instance-%d", i+10)
		s.noteHookForwarder(r, now.Add(time.Duration(i)*time.Second))
	}
	h = s.HookIngestion()
	if len(h.Forwarders) != 128 || !h.ForwardersTruncated {
		t.Fatalf("unbounded reports: %d, %v", len(h.Forwarders), h.ForwardersTruncated)
	}
	h.Forwarders[0].Report.State = "error"
	if s.HookIngestion().Forwarders[0].Report.State == "error" {
		t.Fatal("snapshot aliases stored reports")
	}
}

func TestFutureHostReportCannotBecomeRecentWithoutNewReceipt(t *testing.T) {
	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 1, Harness: "codex", ForwarderID: "instance-1", Sequence: 1, TS: base.Add(time.Minute), State: "connected"}
	rows := map[string]HookForwarderSnapshot{"instance-1": {Report: r, ReceivedAt: base}}
	for _, at := range []time.Time{base, base.Add(61 * time.Second)} {
		if got := forwarderSnapshots(rows, at)[0].Freshness; got != "unverified" {
			t.Fatalf("freshness at %v = %s", at, got)
		}
	}
	if got := forwarderSnapshots(rows, base.Add(3*time.Minute))[0].Freshness; got != "stale" {
		t.Fatalf("expired receipt = %s", got)
	}
}

func TestStructuredHostHealthOwnsMutableMetadataAndRejectsDowngrade(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.TrackHookIngestion()
	now := time.Now().UTC()
	r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 2, Harness: "hermes", ForwarderID: "host", Sequence: 1, TS: now, State: "error", Pending: 2,
		Health: &hookrun.ForwarderHealth{SourceState: "connected", DeliveryError: hookrun.ErrRecorderFailed, Outbox: &hookrun.OutboxHealth{Persisted: 1, Recovered: 1}}}
	s.noteHookForwarder(r, now)
	r.Health.Outbox.Persisted = 0
	r.Health.DeliveryError = ""
	h := s.HookIngestion()
	if h.Forwarders[0].Report.Health.Outbox.Persisted != 1 || h.Forwarders[0].Report.Health.DeliveryError != "recorder-failed" {
		t.Fatal("caller mutation changed retained health")
	}
	h.Forwarders[0].Report.Health.SourceState = "disconnected"
	h.Forwarders[0].Report.Health.Outbox.Persisted = 0
	if h := s.HookIngestion(); h.Forwarders[0].Report.Health.SourceState != "connected" || h.Forwarders[0].Report.Health.Outbox.Persisted != 1 {
		t.Fatal("snapshot mutation changed retained health")
	}
	r.Version, r.Health, r.State, r.Sequence = 1, nil, "connected", 2
	s.noteHookForwarder(r, now)
	if h := s.HookIngestion(); h.Rejected != 1 || h.Forwarders[0].Report.Sequence != 1 {
		t.Fatal("same-instance downgrade erased structured failure")
	}
}
