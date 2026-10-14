// Package forwarder delivers normalized hook metadata independently of hook
// execution. The host owns source subscriptions and calls SetSourceState when
// their state changes. Queues are bounded; optional outboxes persist metadata.
package forwarder

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

var (
	ErrFull     = hookrun.ErrQueueFull
	ErrConflict = hookrun.ErrDeliveryConflict
	ErrRunning  = errors.New("hook forwarder is already running")
)

// Sender acknowledges one metadata record. Send must honor cancellation and
// must not return success until the destination accepts the record. An error
// may follow a successful write, so destinations must tolerate duplicate IDs.
// Calls are serialized. Raw transport errors are never included in reports.
type Sender interface {
	Send(context.Context, []byte) error
}

type Config struct {
	Harness        string
	SessionID      string // Empty for a host serving multiple sessions.
	Sender         Sender
	Capacity       int           // Default 256, maximum 4096, including the in-flight record.
	RetryInterval  time.Duration // Default one second.
	ReportInterval time.Duration // Default 30 seconds, maximum one minute.
	SendTimeout    time.Duration // Default ten seconds.
	OutboxDir      string        // Optional absolute private directory, owned until Close.
	OutboxMaxBytes int64         // Database budget, default 8 MiB; rollback journals can use additional space.
}

// Snapshot is local host diagnostics, available even when reports cannot reach
// the recorder. ReportError means the last report attempt failed. Counters count
// completion delivery attempts and overflow, never failed report attempts.
type Snapshot struct {
	ForwarderID      string
	State            string
	Pending          uint64
	DeliveryFailures uint64
	Dropped          uint64
	ReportError      bool
	Running          bool
	Persisted        uint64 // Subset of Pending committed to the optional outbox.
	Recovered        uint64 // Pending records loaded when this client opened its outbox.
	StorageError     bool
	StorageFull      bool
	Closed           bool
	Health           hookrun.ForwarderHealth
}

type queued struct {
	id, session string
	data        []byte
	persisted   bool
}

// Client permits concurrent capture and diagnostics while one Run worker owns
// delivery. Enqueue does no I/O and never waits for the destination.
type Client struct {
	mu                                                   sync.Mutex
	config                                               Config
	id                                                   string
	source                                               string
	queue                                                []queued
	failures, dropped, sequence                          uint64
	reportError, running                                 bool
	captureError, deliveryCode                           hookrun.FailureCode
	wake                                                 chan struct{}
	persistWake                                          chan struct{}
	outbox                                               *outbox
	recovered                                            uint64
	persistError, ackError, persistFull, ackFull, closed bool
}

func New(config Config) (*Client, error) {
	if config.Capacity == 0 {
		config.Capacity = 256
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = time.Second
	}
	if config.ReportInterval == 0 {
		config.ReportInterval = 30 * time.Second
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = 10 * time.Second
	}
	if config.OutboxDir != "" {
		if config.OutboxMaxBytes == 0 {
			config.OutboxMaxBytes = 8 * 1024 * 1024
		}
		if config.OutboxMaxBytes < 65536 || config.OutboxMaxBytes > 1024*1024*1024 {
			return nil, errors.New("invalid hook outbox budget")
		}
		if _, ok := config.Sender.(DurableSender); !ok {
			return nil, errors.New("hook outbox requires durable destination acknowledgment")
		}
	} else if config.OutboxMaxBytes != 0 {
		return nil, errors.New("hook outbox budget requires a directory")
	}
	if config.Sender == nil || config.Capacity < 1 || config.Capacity > 4096 || config.RetryInterval < 0 || config.ReportInterval < 0 || config.ReportInterval > time.Minute || config.SendTimeout < 0 {
		return nil, errors.New("invalid hook forwarder configuration")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 1, Harness: config.Harness, SessionID: config.SessionID, ForwarderID: id, Sequence: 1, TS: time.Now().UTC(), State: "disconnected"}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	c := &Client{config: config, id: id, source: "unknown", wake: make(chan struct{}, 1), persistWake: make(chan struct{}, 1)}
	if config.OutboxDir != "" {
		c.outbox, c.queue, err = openOutbox(config)
		if err != nil {
			return nil, err
		}
		c.recovered = uint64(len(c.queue))
	}
	return c, nil
}

func newID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errors.New("cannot allocate hook delivery identity")
	}
	return hex.EncodeToString(id[:]), nil
}

// Enqueue freezes a validated metadata record. Duplicate pending IDs with the
// same metadata are idempotent. Overflow rejects the newest record and leaves
// previously accepted records intact. Invalid records do not count as drops.
func (c *Client) Enqueue(record hookrun.Record) (err error) {
	if err := record.Validate(); err != nil {
		return c.captureResult(err)
	}
	if record.Harness != c.config.Harness || c.config.SessionID != "" && record.SessionID != c.config.SessionID {
		return c.captureResult(hookrun.ErrScopeMismatch)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return c.captureResult(hookrun.ErrInvalidInput)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { err = c.captureResultLocked(err) }()
	if c.closed {
		return ErrClosed
	}
	for _, item := range c.queue {
		if item.id == record.ID && item.session == record.SessionID {
			if bytes.Equal(item.data, data) {
				return nil
			}
			return ErrConflict
		}
	}
	if len(c.queue) >= c.config.Capacity {
		c.dropped++
		c.notify()
		return ErrFull
	}
	c.queue = append(c.queue, queued{id: record.ID, session: record.SessionID, data: data})
	c.notify()
	select {
	case c.persistWake <- struct{}{}:
	default:
	}
	return nil
}

// Only safe, operation-specific codes enter diagnostics. A valid admission
// clears capture failures; it never clears delivery or persistence failures.
func (c *Client) captureResult(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.captureResultLocked(err)
}

func (c *Client) captureResultLocked(err error) error {
	code := hookrun.ErrorCode(err)
	if err != nil && !errors.Is(err, ErrClosed) {
		switch code {
		case hookrun.ErrInvalidInput, hookrun.ErrUnsupportedProtocol, hookrun.ErrScopeMismatch, hookrun.ErrDeliveryConflict, hookrun.ErrQueueFull:
		default:
			code = hookrun.ErrInvalidInput
		}
		err = code
	}
	if !c.closed && c.captureError != code {
		c.captureError = code
		c.notify()
	}
	return err
}

// SetSourceState takes an explicit host observation: connected, disconnected,
// or error. Source state starts unknown and reports are withheld until this is
// called. Completion traffic and worker shutdown do not establish source state.
func (c *Client) SetSourceState(state string) error {
	if state != "connected" && state != "disconnected" && state != "error" {
		return errors.New("invalid hook source state")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if state != c.source {
		c.source = state
		c.notify()
	}
	return nil
}

func (c *Client) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Client) snapshotLocked() Snapshot {
	var persisted uint64
	for _, item := range c.queue {
		if item.persisted {
			persisted++
		}
	}
	h := hookrun.ForwarderHealth{SourceState: c.source, CaptureError: c.captureError, DeliveryError: c.deliveryCode, ReportError: c.reportError}
	if c.outbox != nil {
		h.Outbox = &hookrun.OutboxHealth{Persisted: persisted, Recovered: c.recovered}
		if c.persistError || c.ackError {
			h.Outbox.Error = hookrun.ErrOutboxFailed
		}
		if c.persistFull || c.ackFull {
			h.Outbox.Error = hookrun.ErrOutboxFull
		}
	}
	return Snapshot{ForwarderID: c.id, State: h.State(), Pending: uint64(len(c.queue)), DeliveryFailures: c.failures, Dropped: c.dropped, ReportError: c.reportError, Running: c.running, Persisted: persisted, Recovered: c.recovered, StorageError: c.persistError || c.ackError, StorageFull: c.persistFull || c.ackFull, Closed: c.closed, Health: h}
}

func (c *Client) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked()
}

func (c *Client) send(ctx context.Context, data []byte) error {
	attempt, cancel := context.WithTimeout(ctx, c.config.SendTimeout)
	defer cancel()
	return c.config.Sender.Send(attempt, bytes.Clone(data))
}

func (c *Client) report(ctx context.Context) (failed bool) {
	c.mu.Lock()
	if c.source == "unknown" {
		c.mu.Unlock()
		return false
	}
	c.sequence++
	s := c.snapshotLocked()
	r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 2, Harness: c.config.Harness, SessionID: c.config.SessionID, ForwarderID: c.id, Sequence: c.sequence, TS: time.Now().UTC(), State: s.State, Pending: s.Pending, DeliveryFailures: s.DeliveryFailures, Dropped: s.Dropped, Health: &s.Health}
	c.mu.Unlock()
	data, err := json.Marshal(r)
	if err == nil {
		err = c.send(ctx, data)
	}
	c.mu.Lock()
	if ctx.Err() == nil {
		if c.reportError && err == nil {
			c.notify()
		}
		c.reportError = err != nil
	}
	c.mu.Unlock()
	return err != nil
}

func (c *Client) deliverOne(ctx context.Context) (failed bool) {
	if ctx.Err() == nil {
		c.mu.Lock()
		if len(c.queue) == 0 {
			c.mu.Unlock()
			return false
		}
		item := c.queue[0]
		c.mu.Unlock()
		var err error
		if c.outbox != nil {
			attempt, cancel := context.WithTimeout(ctx, c.config.SendTimeout)
			err = c.config.Sender.(DurableSender).SendDurable(attempt, bytes.Clone(item.data))
			cancel()
		} else {
			err = c.send(ctx, item.data)
		}
		c.mu.Lock()
		if err != nil {
			// Shutdown cancellation is not a failed delivery attempt. Keep the
			// original metadata queued, including an ambiguous append.
			if ctx.Err() == nil {
				c.failures++
				c.deliveryCode = hookrun.ErrorCode(err)
				if c.deliveryCode != hookrun.ErrRecorderUnavailable {
					c.deliveryCode = hookrun.ErrRecorderFailed
				}
			}
			c.mu.Unlock()
			return true
		}
		c.deliveryCode = ""
		c.mu.Unlock()
		if c.outbox != nil {
			err = c.outbox.ack(ctx, item)
			c.mu.Lock()
			if ctx.Err() == nil {
				c.ackError = err != nil
				c.ackFull = isOutboxFull(err)
			}
			c.mu.Unlock()
			if err != nil {
				return true
			}
			select {
			case c.persistWake <- struct{}{}:
			default:
			}
		}
		c.mu.Lock()
		c.queue[0] = queued{}
		c.queue = c.queue[1:]
		if c.captureError == hookrun.ErrQueueFull {
			c.captureError = ""
		}
		c.mu.Unlock()
	}
	return false
}

// Run delivers until cancellation. There is one worker per client. Cancellation
// retains pending metadata for a later Run on this same client; it does not
// claim delivery or persistence. With an outbox, only confirmed persisted
// records survive releasing the client. Close releases outbox ownership.
func (c *Client) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	if c.running {
		c.mu.Unlock()
		return ErrRunning
	}
	c.running = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.running = false; c.mu.Unlock() }()
	if c.outbox != nil {
		persistCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); c.persist(persistCtx) }()
		defer func() { stop(); <-done }()
	}
	retry := time.NewTicker(c.config.RetryInterval)
	heartbeat := time.NewTicker(c.config.ReportInterval)
	defer retry.Stop()
	defer heartbeat.Stop()
	deliver := true
	var nextAttempt time.Time
	var nextReportAttempt time.Time
	report := func() {
		if time.Now().Before(nextReportAttempt) {
			return
		}
		if c.report(ctx) {
			nextReportAttempt = time.Now().Add(c.config.RetryInterval)
		} else {
			nextReportAttempt = time.Time{}
		}
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if deliver {
			report()
			if !time.Now().Before(nextAttempt) && c.deliveryReady() {
				failed := c.deliverOne(ctx)
				if ctx.Err() != nil {
					return ctx.Err()
				}
				report()
				if failed {
					// Capture wakeups cannot bypass a failed attempt's delay.
					nextAttempt = time.Now().Add(c.config.RetryInterval)
				} else {
					nextAttempt = time.Time{}
					// Service source observations and reports between records,
					// including during a continuously replenished backlog.
					if c.deliveryReady() {
						continue
					}
				}
			}
		}
		deliver = false
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.wake:
			deliver = true
		case <-heartbeat.C:
			report()
		case <-retry.C:
			s := c.Snapshot()
			deliver = s.Pending > 0 || s.ReportError
		}
	}
}

func (c *Client) deliveryReady() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queue) > 0 && (c.outbox == nil || c.queue[0].persisted)
}

// Close releases outbox ownership after Run has stopped. It rejects concurrent
// delivery and reports any accepted metadata not yet confirmed on disk. Close
// does not flush capture synchronously; wait for Persisted == Pending first.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return ErrRunning
	}
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	s := c.snapshotLocked()
	c.mu.Unlock()
	var err error
	if c.outbox != nil && c.outbox.close() != nil {
		err = ErrStorage
	}
	if s.Pending > s.Persisted {
		err = errors.Join(err, ErrUnpersisted)
	}
	return err
}
