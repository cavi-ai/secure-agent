package forwarder_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/forwarder"
)

func snapshotHealth(t *testing.T, c *forwarder.Client) hookrun.ForwarderHealth {
	t.Helper()
	data, err := json.Marshal(c.Snapshot())
	var s struct{ Health *hookrun.ForwarderHealth }
	if err != nil || json.Unmarshal(data, &s) != nil || s.Health == nil {
		t.Fatalf("missing structured local health: %s %v", data, err)
	}
	return *s.Health
}

func TestHarnessCaptureHealthAndRecovery(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "openclaw", "hermes", "opencode"} {
		t.Run(harness, func(t *testing.T) {
			c, err := forwarder.New(forwarder.Config{Harness: harness, SessionID: "s", Sender: &destination{}, Capacity: 1})
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetSourceState("connected")
			r := hookrun.Record{Type: "hook_run", Version: 1, Harness: harness, SessionID: "s", ID: harness + ":one", TS: time.Now().UTC(), Event: "stop", Status: "ok"}
			invalid := r
			invalid.Event = "/private/input"
			if err := c.Enqueue(invalid); err == nil {
				t.Fatal("invalid input admitted")
			}
			if h := snapshotHealth(t, c); h.CaptureError != "invalid-input" || h.SourceState != "connected" {
				t.Fatalf("capture error lost source: %+v", h)
			}
			if err := c.Enqueue(r); err != nil {
				t.Fatal(err)
			}
			if h := snapshotHealth(t, c); h.CaptureError != "" {
				t.Fatalf("valid admission did not clear capture error: %+v", h)
			}
			foreign := r
			foreign.SessionID = "other"
			if err := c.Enqueue(foreign); err == nil {
				t.Fatal("foreign session admitted")
			}
			if h := snapshotHealth(t, c); h.CaptureError != "scope-mismatch" {
				t.Fatalf("scope failure not classified: %+v", h)
			}
			if err := c.Enqueue(r); err != nil {
				t.Fatal(err)
			}
			conflict := r
			conflict.Status = "error"
			if err := c.Enqueue(conflict); !errors.Is(err, forwarder.ErrConflict) {
				t.Fatalf("conflict: %v", err)
			}
			r.ID = harness + ":two"
			if err := c.Enqueue(r); !errors.Is(err, forwarder.ErrFull) {
				t.Fatalf("overflow: %v", err)
			}
			if h := snapshotHealth(t, c); h.CaptureError != "queue-full" || h.Outbox != nil {
				t.Fatalf("overflow or persistence misreported: %+v", h)
			}
			start(t, c)
			eventually(t, func() bool { return c.Snapshot().Pending == 0 })
			if h := snapshotHealth(t, c); h.CaptureError != "" || c.Snapshot().Dropped != 1 {
				t.Fatalf("capacity recovery erased loss or kept active error: %+v", h)
			}
		})
	}
}

func TestDeliveryHealthPreservesSourceAndReportsPersistence(t *testing.T) {
	d := &durableDestination{destination: destination{fail: true}}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d, RetryInterval: 10 * time.Millisecond, OutboxDir: filepath.Join(t.TempDir(), "outbox")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetSourceState("connected")
	_, err = c.Submit([]byte(completion))
	if err != nil {
		t.Fatal(err)
	}
	start(t, c.Client)
	eventually(t, func() bool { return c.Snapshot().DeliveryFailures > 0 })
	h := snapshotHealth(t, c.Client)
	if h.SourceState != "connected" || h.DeliveryError != "recorder-failed" || h.Outbox == nil || h.Outbox.Persisted != 1 || h.Outbox.Error != "" {
		t.Fatalf("independent health collapsed: %+v", h)
	}
	d.mu.Lock()
	d.fail = false
	d.mu.Unlock()
	eventually(t, func() bool { return c.Snapshot().Pending == 0 && !c.Snapshot().ReportError })
	if h := snapshotHealth(t, c.Client); h.DeliveryError != "" || h.Outbox.Persisted != 0 {
		t.Fatalf("recovery not visible: %+v", h)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var reported bool
	for _, line := range d.lines {
		r, ok, err := hookrun.DecodeForwarderReport(line)
		if ok && err == nil && r.Version == 2 && r.Health != nil && r.Health.DeliveryError == "recorder-failed" && r.Health.Outbox.Persisted == 1 {
			reported = true
		}
	}
	if !reported {
		t.Fatal("structured failure stayed local instead of reaching report")
	}
}

func TestMissingRecorderHasStableSafeFailureCode(t *testing.T) {
	err := (forwarder.Recorder{Executable: filepath.Join(t.TempDir(), "missing")}).Send(context.Background(), []byte(`{}`))
	if hookrun.ErrorCode(err) != "recorder-unavailable" {
		t.Fatalf("unclassified recorder error: %v", err)
	}
}

func TestCancellingReportDoesNotInventReportingFailure(t *testing.T) {
	d := &destination{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetSourceState("connected")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	await(t, d.entered)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if h := snapshotHealth(t, c.Client); h.ReportError || h.SourceState != "connected" {
		t.Fatalf("shutdown invented failure or disconnection: %+v", h)
	}
}
