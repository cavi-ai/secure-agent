package forwarder_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/forwarder"
)

type durableDestination struct{ destination }

func (d *durableDestination) Send(ctx context.Context, data []byte) error {
	if _, ok, _ := hookrun.DecodeRecord(data); ok {
		return errors.New("ordinary append cannot acknowledge durable delivery")
	}
	return d.destination.Send(ctx, data)
}

// Unit transport only; process-level acceptance uses the actual recorder.
func (d *durableDestination) SendDurable(ctx context.Context, data []byte) error {
	return d.destination.Send(ctx, data)
}

func runUntilPersisted(t *testing.T, c *forwarder.Client, want uint64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("outbox worker did not stop")
		}
	}()
	eventually(t, func() bool { return c.Snapshot().Persisted == want })
}

func TestOutboxReopensOriginalIDsAndRequiresDurableDelivery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	d := &durableDestination{destination: destination{fail: true}}
	c, err := forwarder.NewCodex(forwarder.Config{OutboxDir: dir, Sender: d})
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Submit([]byte(completion))
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Snapshot(); s.Pending != 1 || s.Persisted != 0 {
		t.Fatalf("capture claimed disk persistence: %+v", s)
	}
	runUntilPersisted(t, c.Client, 1)
	firstID := c.Snapshot().ForwarderID
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Submit([]byte(completion)); !errors.Is(err, forwarder.ErrClosed) {
		t.Fatalf("closed capture: %v", err)
	}
	if _, err := forwarder.NewCodex(forwarder.Config{OutboxDir: dir, Sender: &destination{}}); err == nil {
		t.Fatal("append-only sender accepted for durable queue")
	}
	d2 := &durableDestination{}
	c2, err := forwarder.NewCodex(forwarder.Config{OutboxDir: dir, Sender: d2})
	if err != nil {
		t.Fatal(err)
	}
	if s := c2.Snapshot(); s.Pending != 1 || s.Persisted != 1 || s.Recovered != 1 || s.ForwarderID == firstID || s.State != "unknown" {
		t.Fatalf("reopen: %+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c2.Run(ctx) }()
	eventually(t, func() bool { return c2.Snapshot().Pending == 0 })
	cancel()
	<-done
	if err := c2.Close(); err != nil {
		t.Fatal(err)
	}
	d2.mu.Lock()
	defer d2.mu.Unlock()
	if len(d2.lines) != 1 {
		t.Fatalf("restored deliveries=%d", len(d2.lines))
	}
	r, ok, err := hookrun.DecodeRecord(d2.lines[0])
	if !ok || err != nil || r.ID != id || bytes.Contains(d2.lines[0], []byte("private")) {
		t.Fatalf("restored completion: %+v %v", r, err)
	}
	c3, err := forwarder.NewCodex(forwarder.Config{OutboxDir: dir, Sender: &durableDestination{}})
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if c3.Snapshot().Pending != 0 {
		t.Fatal("acknowledged completion remained in outbox")
	}
}

func TestOutboxOwnershipScopeAndUnpersistedClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	cfg := forwarder.Config{Harness: "hermes", SessionID: "first", Sender: &durableDestination{}, OutboxDir: dir}
	c, err := forwarder.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forwarder.New(cfg); err == nil {
		t.Fatal("second owner acquired outbox")
	}
	r := hookrun.Record{Type: "hook_run", Version: 1, Harness: "hermes", SessionID: "first", ID: "hermes:one", TS: time.Now().UTC(), Event: "pre_tool_call", Status: "ok"}
	if err := c.Enqueue(r); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); !errors.Is(err, forwarder.ErrUnpersisted) {
		t.Fatalf("unsaved close: %v", err)
	}
	cfg.SessionID = "other"
	if _, err := forwarder.New(cfg); err == nil {
		t.Fatal("outbox reopened under a different scope")
	}
	bad := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(bad, 0755); err != nil {
		t.Fatal(err)
	}
	cfg.OutboxDir = bad
	if _, err := forwarder.New(cfg); err == nil {
		t.Fatal("publicly readable outbox accepted")
	}
}

func TestOutboxBudgetAndStorageFailureDoNotBlockCapture(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	d := &durableDestination{destination: destination{fail: true}}
	c, err := forwarder.New(forwarder.Config{Harness: "hermes", Sender: d, OutboxDir: dir, OutboxMaxBytes: 65536, Capacity: 100, RetryInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		r := hookrun.Record{Type: "hook_run", Version: 2, Harness: "hermes", SessionID: strings.Repeat("s", 255), ID: fmt.Sprintf("hermes:%03d", i), TS: time.Now().UTC(), Event: strings.Repeat("e", 128), Status: "ok", Evidence: &hookrun.Evidence{HandlerID: strings.Repeat("h", 255), ConfigID: strings.Repeat("c", 255), OperationID: strings.Repeat("o", 255)}}
		if err := c.Enqueue(r); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	eventually(t, func() bool { s := c.Snapshot(); return s.StorageFull && s.DeliveryFailures > 0 })
	s := c.Snapshot()
	if !s.StorageError || s.Pending != 100 || s.Persisted == 0 || s.Persisted == 100 {
		t.Fatalf("storage quota: %+v", s)
	}
	if s.Health.Outbox == nil || s.Health.Outbox.Error != "outbox-full" || s.Health.Outbox.Persisted != s.Persisted || s.Health.DeliveryError == "" {
		t.Fatalf("storage and recorder failures were not kept separate: %+v", s.Health)
	}
	if fi, err := os.Stat(filepath.Join(dir, "outbox.db")); err != nil || fi.Size() > 65536 {
		t.Fatalf("disk budget exceeded: %v %v", fi, err)
	}
	cancel()
	<-done
	if err := c.Close(); !errors.Is(err, forwarder.ErrUnpersisted) {
		t.Fatalf("partially saved close: %v", err)
	}
	// The unreadable/locked database is not accessed from the capture callback.
	c, err = forwarder.New(forwarder.Config{Harness: "hermes", Sender: d, OutboxDir: dir, OutboxMaxBytes: 65536, Capacity: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	db, err := sql.Open("sqlite", filepath.Join(dir, "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("ROLLBACK")
	queued := make(chan error, 1)
	go func() {
		queued <- c.Enqueue(hookrun.Record{Type: "hook_run", Version: 1, Harness: "hermes", SessionID: "new", ID: "hermes:new", TS: time.Now().UTC(), Event: "pre_tool_call", Status: "ok"})
	}()
	select {
	case err := <-queued:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("capture waited for disk")
	}
}

func TestOutboxSurvivesKilledForwardingProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestOutboxCrashWorker$")
	child.Env = append(os.Environ(), "SECURE_AGENT_OUTBOX_TEST_CHILD=1", "SECURE_AGENT_OUTBOX_TEST_DIR="+dir)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	var saved struct{ ID, ForwarderID string }
	if err := json.NewDecoder(stdout).Decode(&saved); err != nil {
		t.Fatalf("child did not confirm persistence: %v %s", err, stderr.String())
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("child was not killed")
	}
	d := &durableDestination{}
	c, err := forwarder.NewCodex(forwarder.Config{OutboxDir: dir, Sender: d})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	if s := c.Snapshot(); s.Recovered != 1 || s.Persisted != 1 || s.ForwarderID == saved.ForwarderID {
		t.Fatalf("crash recovery: %+v", s)
	}
	start(t, c.Client)
	eventually(t, func() bool { return c.Snapshot().Pending == 0 })
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.lines) != 1 {
		t.Fatalf("replay count=%d", len(d.lines))
	}
	if r, ok, err := hookrun.DecodeRecord(d.lines[0]); !ok || err != nil || r.ID != saved.ID {
		t.Fatalf("replay lost identity: %+v %v", r, err)
	}
}

// Helper is inert in ordinary suite runs. The parent kills this test process
// after the real SQLite commit, without Run cancellation or Close cleanup.
func TestOutboxCrashWorker(t *testing.T) {
	if os.Getenv("SECURE_AGENT_OUTBOX_TEST_CHILD") != "1" {
		return
	}
	c, err := forwarder.NewCodex(forwarder.Config{OutboxDir: os.Getenv("SECURE_AGENT_OUTBOX_TEST_DIR"), Sender: &durableDestination{destination: destination{fail: true}}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Submit([]byte(completion))
	if err != nil {
		t.Fatal(err)
	}
	go c.Run(context.Background())
	eventually(t, func() bool { return c.Snapshot().Persisted == 1 })
	if err := json.NewEncoder(os.Stdout).Encode(struct{ ID, ForwarderID string }{id, c.Snapshot().ForwarderID}); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestOutboxRejectsUnsupportedDatabasePageSize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	cfg := forwarder.Config{OutboxDir: dir, Sender: &durableDestination{destination: destination{fail: true}}}
	c, err := forwarder.NewCodex(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Submit([]byte(completion)); err != nil {
		t.Fatal(err)
	}
	runUntilPersisted(t, c.Client, 1)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA page_size=8192; VACUUM"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	for i := 0; i < 2; i++ {
		c, err := forwarder.NewCodex(cfg)
		if err == nil {
			c.Close()
			t.Fatal("unsupported page size bypassed replay checks")
		}
	}
	db, err = sql.Open("sqlite", filepath.Join(dir, "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA page_size=4096; VACUUM"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	c, err = forwarder.NewCodex(cfg)
	if err != nil {
		t.Fatalf("rejected open leaked ownership: %v", err)
	}
	defer c.Close()
	if c.Snapshot().Persisted != 1 {
		t.Fatal("rejected open discarded pending metadata")
	}
}
