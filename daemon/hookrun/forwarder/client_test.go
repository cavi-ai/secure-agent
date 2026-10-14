package forwarder_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/forwarder"
)

const completion = `{"method":"hook/completed","params":{"threadId":"session-1","run":{"id":"stop:0:/private/hooks.json","eventName":"stop","status":"blocked","completedAt":1791882001,"durationMs":7,"entries":[{"kind":"feedback","text":"private feedback"}]}}}`

// This transport models a blocked or unavailable destination, including an
// ambiguous acknowledgement after a write. The recorder test uses a real process.
type destination struct {
	mu      sync.Mutex
	fail    bool
	lines   [][]byte
	entered chan struct{}
	release chan struct{}
}

func (d *destination) Send(ctx context.Context, line []byte) error {
	if d.entered != nil {
		select {
		case d.entered <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.release:
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lines = append(d.lines, bytes.Clone(line))
	if d.fail {
		return errors.New("private destination error")
	}
	return nil
}

func start(t *testing.T, c *forwarder.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("forwarder stopped unexpectedly: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("forwarder did not stop")
		}
	})
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("forwarder did not reach expected state")
		}
		time.Sleep(time.Millisecond)
	}
}

func await(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("transport did not receive delivery")
	}
}

func TestRetryKeepsIdentityAndRecoveryKeepsFailureCount(t *testing.T) {
	d := &destination{fail: true}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d, Capacity: 2, RetryInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSourceState("connected"); err != nil {
		t.Fatal(err)
	}
	id, err := c.Submit([]byte(completion))
	if err != nil || id == "" {
		t.Fatalf("submit: %q %v", id, err)
	}
	start(t, c.Client)
	eventually(t, func() bool { return c.Snapshot().DeliveryFailures >= 1 })
	failed := c.Snapshot()
	if failed.Pending != 1 || failed.State != "error" || !failed.ReportError {
		t.Fatalf("outage: %+v", failed)
	}
	d.mu.Lock()
	d.fail = false
	d.mu.Unlock()
	eventually(t, func() bool { s := c.Snapshot(); return s.Pending == 0 && s.State == "connected" && !s.ReportError })
	if c.Snapshot().DeliveryFailures < failed.DeliveryFailures {
		t.Fatal("recovery erased failures")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var attempts int
	var prior uint64
	for _, line := range d.lines {
		if bytes.Contains(line, []byte("private")) {
			t.Fatal("raw notification retained in delivery")
		}
		if r, ok, err := hookrun.DecodeRecord(line); ok {
			if err != nil || r.ID != id || r.Status != "block" || r.Chars != 16 {
				t.Fatalf("retry metadata: %+v %v", r, err)
			}
			attempts++
		} else if r, ok, err := hookrun.DecodeForwarderReport(line); !ok || err != nil || r.Sequence <= prior {
			t.Fatalf("report: %+v %v", r, err)
		} else {
			prior = r.Sequence
		}
	}
	if attempts < 2 {
		t.Fatal("failed completion was not retried")
	}
}

func TestBlockedDestinationCannotBlockCaptureAndOverflowIsExplicit(t *testing.T) {
	d := &destination{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d, Capacity: 1, SendTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSourceState("disconnected"); err != nil {
		t.Fatal(err)
	}
	start(t, c.Client)
	await(t, d.entered)
	done := make(chan error, 1)
	go func() { _, err := c.Submit([]byte(completion)); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("capture blocked on transport")
	}
	if _, err := c.Submit([]byte(completion)); !errors.Is(err, forwarder.ErrFull) {
		t.Fatalf("overflow: %v", err)
	}
	if s := c.Snapshot(); s.Pending != 1 || s.Dropped != 1 || s.State != "error" || s.Health.SourceState != "disconnected" {
		t.Fatalf("queue: %+v", s)
	}
}

func TestQueueOwnsMetadataAndEnforcesScope(t *testing.T) {
	d := &destination{}
	c, err := forwarder.New(forwarder.Config{Harness: "hermes", SessionID: "session-1", Sender: d})
	if err != nil {
		t.Fatal(err)
	}
	r := hookrun.Record{Type: "hook_run", Version: 2, Harness: "hermes", SessionID: "session-1", ID: "hermes:one", TS: time.Now().UTC(), Event: "pre_tool_call", Status: "ok", Evidence: &hookrun.Evidence{HandlerID: "handler-1"}}
	if err := c.Enqueue(r); err != nil {
		t.Fatal(err)
	}
	if err := c.Enqueue(r); err != nil || c.Snapshot().Pending != 1 {
		t.Fatal("pending retry duplicated")
	}
	r.Evidence.HandlerID = "changed"
	if err := c.Enqueue(r); !errors.Is(err, forwarder.ErrConflict) {
		t.Fatalf("changed retry: %v", err)
	}
	r.ID = "hermes:two"
	r.SessionID = "session-2"
	if err := c.Enqueue(r); err == nil {
		t.Fatal("foreign session accepted")
	}
	r.SessionID = "session-1"
	r.Harness = "codex"
	if err := c.Enqueue(r); err == nil {
		t.Fatal("foreign harness accepted")
	}
	start(t, c)
	eventually(t, func() bool { return c.Snapshot().Pending == 0 })
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, line := range d.lines {
		if bytes.Contains(line, []byte("hook_run")) {
			var got hookrun.Record
			_ = json.Unmarshal(line, &got)
			if got.Evidence.HandlerID != "handler-1" {
				t.Fatal("caller mutation changed queued metadata")
			}
		}
	}
}

func TestCodexIgnoresUnrelatedMessagesAndRejectsInvalidCompletions(t *testing.T) {
	c, err := forwarder.NewCodex(forwarder.Config{Sender: &destination{}})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := c.Submit([]byte(`{"method":"hook/started"}`)); id != "" || err != nil {
		t.Fatalf("unrelated: %q %v", id, err)
	}
	for _, raw := range []string{`{"private`, `{"method":"hook/completed","params":{}}`} {
		if _, err := c.Submit([]byte(raw)); err == nil || bytes.Contains([]byte(err.Error()), []byte("private")) {
			t.Fatalf("invalid notification: %v", err)
		}
	}
	if c.Snapshot().Pending != 0 || c.Snapshot().Dropped != 0 {
		t.Fatal("invalid input became queued or dropped completion")
	}
	if err := c.SetSourceState("invented"); err == nil {
		t.Fatal("unsupported source state accepted")
	}
}

func TestNewCompletionsCannotBypassRetryDelay(t *testing.T) {
	d := &destination{fail: true}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d, Capacity: 2, RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetSourceState("connected")
	_, _ = c.Submit([]byte(completion))
	start(t, c.Client)
	eventually(t, func() bool { return c.Snapshot().DeliveryFailures >= 1 })
	for i := 0; i < 10; i++ {
		if _, err := c.Submit([]byte(completion)); err != nil && !errors.Is(err, forwarder.ErrFull) {
			t.Fatal(err)
		}
	}
	time.Sleep(30 * time.Millisecond)
	if got := c.Snapshot().DeliveryFailures; got != 1 {
		t.Fatalf("capture bypassed retry delay: %d attempts", got)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.lines) != 2 {
		t.Fatalf("capture bypassed report retry delay: %d total sends; want one report and one completion", len(d.lines))
	}
}

func TestCancellationRetainsPendingIdentityForRestart(t *testing.T) {
	d := &destination{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d, SendTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Submit([]byte(completion))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	await(t, d.entered)
	if err := c.Run(context.Background()); !errors.Is(err, forwarder.ErrRunning) {
		t.Fatalf("second worker: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown ignored cancellation")
	}
	if s := c.Snapshot(); s.Pending != 1 || s.DeliveryFailures != 0 || s.Running {
		t.Fatalf("shutdown: %+v", s)
	}
	close(d.release)
	start(t, c.Client)
	eventually(t, func() bool { return c.Snapshot().Pending == 0 })
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, line := range d.lines {
		if r, ok, _ := hookrun.DecodeRecord(line); ok && r.ID != id {
			t.Fatal("restart changed pending identity")
		}
	}
}

func TestIdleReportsRecoverAndHeartbeatFollowsExplicitSourceState(t *testing.T) {
	d := &destination{fail: true}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d, RetryInterval: 10 * time.Millisecond, ReportInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSourceState("disconnected"); err != nil {
		t.Fatal(err)
	}
	start(t, c.Client)
	eventually(t, func() bool { return c.Snapshot().ReportError })
	if s := c.Snapshot(); s.State != "disconnected" || s.DeliveryFailures != 0 {
		t.Fatalf("report outage invented source or completion failure: %+v", s)
	}
	d.mu.Lock()
	d.fail = false
	d.mu.Unlock()
	if err := c.SetSourceState("connected"); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		connected := 0
		for _, line := range d.lines {
			if r, ok, err := hookrun.DecodeForwarderReport(line); ok && err == nil && r.State == "connected" {
				connected++
			}
		}
		return connected >= 2
	})
	if s := c.Snapshot(); s.ReportError || s.Pending != 0 || s.DeliveryFailures != 0 {
		t.Fatalf("idle recovery: %+v", s)
	}
}

func TestConfigurationAndRecorderErrorsStayBoundedAndPrivate(t *testing.T) {
	for _, cfg := range []forwarder.Config{
		{Harness: "codex"},
		{Harness: "unknown", Sender: &destination{}},
		{Harness: "codex", Sender: &destination{}, Capacity: 4097},
		{Harness: "codex", Sender: &destination{}, RetryInterval: -time.Second},
		{Harness: "codex", Sender: &destination{}, ReportInterval: 3 * time.Minute},
		{Harness: "codex", Sender: &destination{}, SendTimeout: -time.Second},
		{Harness: "codex", Sender: &destination{}, SessionID: "/private/session"},
	} {
		if _, err := forwarder.New(cfg); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", cfg)
		}
	}
	if _, err := forwarder.NewCodex(forwarder.Config{Harness: "hermes", Sender: &destination{}}); err == nil {
		t.Fatal("Codex wrapper accepted foreign harness")
	}
	for _, path := range []string{"relative-private", "/nonexistent-private/recorder"} {
		err := (forwarder.Recorder{Executable: path}).Send(context.Background(), nil)
		if err == nil || bytes.Contains([]byte(err.Error()), []byte("private")) {
			t.Fatalf("recorder leaked transport error: %v", err)
		}
	}
}

func TestCompletionsDoNotInventSourceConnectivity(t *testing.T) {
	d := &destination{}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d})
	if err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().State != "unknown" {
		t.Fatal("missing source observation became disconnected")
	}
	if _, err := c.Submit([]byte(completion)); err != nil {
		t.Fatal(err)
	}
	start(t, c.Client)
	eventually(t, func() bool { return c.Snapshot().Pending == 0 })
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, line := range d.lines {
		if _, ok, _ := hookrun.DecodeForwarderReport(line); ok {
			t.Fatal("completion traffic invented a source report")
		}
	}
}

func TestEqualExecutionIDsInDifferentSessionsStaySeparate(t *testing.T) {
	c, err := forwarder.New(forwarder.Config{Harness: "hermes", Sender: &destination{}})
	if err != nil {
		t.Fatal(err)
	}
	r := hookrun.Record{Type: "hook_run", Version: 1, Harness: "hermes", SessionID: "first", ID: "hermes:one", TS: time.Now().UTC(), Event: "pre_tool_call", Status: "ok"}
	if err := c.Enqueue(r); err != nil {
		t.Fatal(err)
	}
	r.SessionID = "second"
	if err := c.Enqueue(r); err != nil {
		t.Fatalf("valid execution in another session rejected: %v", err)
	}
	if c.Snapshot().Pending != 2 {
		t.Fatal("distinct sessions merged")
	}
}

type completionGate struct {
	destination
	entered, release chan struct{}
}

func (d *completionGate) Send(ctx context.Context, line []byte) error {
	if err := d.destination.Send(ctx, line); err != nil {
		return err
	}
	if _, ok, _ := hookrun.DecodeRecord(line); ok {
		d.entered <- struct{}{}
		select {
		case <-d.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestBacklogCannotStarveSourceReports(t *testing.T) {
	d := &completionGate{entered: make(chan struct{}, 3), release: make(chan struct{}, 3)}
	c, err := forwarder.NewCodex(forwarder.Config{Sender: d, ReportInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Submit([]byte(completion)); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetSourceState("connected")
	start(t, c.Client)
	await(t, d.entered)
	_ = c.SetSourceState("disconnected")
	d.release <- struct{}{}
	eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, line := range d.lines {
			if r, ok, err := hookrun.DecodeForwarderReport(line); ok && err == nil && r.State == "disconnected" && r.Pending > 0 {
				return true
			}
		}
		return false
	})
	d.release <- struct{}{}
	d.release <- struct{}{}
}
