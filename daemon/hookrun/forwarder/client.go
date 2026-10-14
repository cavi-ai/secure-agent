// Package forwarder delivers normalized hook metadata independently of hook
// execution. The host owns source subscriptions and calls SetSourceState when
// their state changes. Queues are bounded, in memory, and do not survive exit.
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
	ErrFull     = errors.New("hook delivery queue is full; completion dropped")
	ErrConflict = errors.New("hook delivery id already queued with different metadata")
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
}

type queued struct {
	id, session string
	data        []byte
}

// Client permits concurrent capture and diagnostics while one Run worker owns
// delivery. Enqueue does no I/O and never waits for the destination.
type Client struct {
	mu                                  sync.Mutex
	config                              Config
	id                                  string
	source                              string
	queue                               []queued
	failures, dropped, sequence         uint64
	deliveryError, reportError, running bool
	wake                                chan struct{}
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
	return &Client{config: config, id: id, source: "unknown", wake: make(chan struct{}, 1)}, nil
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
func (c *Client) Enqueue(record hookrun.Record) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if record.Harness != c.config.Harness || c.config.SessionID != "" && record.SessionID != c.config.SessionID {
		return errors.New("hook completion does not match forwarder scope")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return errors.New("cannot encode hook completion metadata")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
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
	return nil
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
	state := c.source
	if c.deliveryError {
		state = "error"
	}
	return Snapshot{ForwarderID: c.id, State: state, Pending: uint64(len(c.queue)), DeliveryFailures: c.failures, Dropped: c.dropped, ReportError: c.reportError, Running: c.running}
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
	r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 1, Harness: c.config.Harness, SessionID: c.config.SessionID, ForwarderID: c.id, Sequence: c.sequence, TS: time.Now().UTC(), State: s.State, Pending: s.Pending, DeliveryFailures: s.DeliveryFailures, Dropped: s.Dropped}
	c.mu.Unlock()
	data, err := json.Marshal(r)
	if err == nil {
		err = c.send(ctx, data)
	}
	c.mu.Lock()
	c.reportError = err != nil
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
		err := c.send(ctx, item.data)
		c.mu.Lock()
		if err != nil {
			// Shutdown cancellation is not a failed delivery attempt. Keep the
			// original metadata queued, including an ambiguous append.
			if ctx.Err() == nil {
				c.failures++
				c.deliveryError = true
			}
			c.mu.Unlock()
			return true
		}
		c.queue[0] = queued{}
		c.queue = c.queue[1:]
		c.deliveryError = false
		c.mu.Unlock()
	}
	return false
}

// Run delivers until cancellation. There is one worker per client. Cancellation
// retains pending metadata for a later Run on this same client; it does not
// claim delivery or persistence. Releasing the client loses its in-memory queue.
func (c *Client) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return ErrRunning
	}
	c.running = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.running = false; c.mu.Unlock() }()
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
			if !time.Now().Before(nextAttempt) && c.Snapshot().Pending > 0 {
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
					if c.Snapshot().Pending > 0 {
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
