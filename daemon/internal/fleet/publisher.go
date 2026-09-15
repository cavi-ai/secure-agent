// Package fleet — delivery fan-out: subscribers register per-kind sinks, and
// the daemon's drain loop calls Publish for each flag/incident/guard decision.
package fleet

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"
	"sync/atomic"
)

// maxInFlightDeliveries bounds concurrent deliveries. Each delivery can live
// ~20s (HTTP timeout + retry budget), so without a cap a flag storm spawns an
// unbounded goroutine pile all hammering a dead collector. Overflow is dropped
// with a counter — delivery is best-effort by design; blocking the daemon is
// not an option.
const maxInFlightDeliveries = 64

// Publisher fans an event payload out to every subscribed sink. Delivery is
// asynchronous and best-effort: a dead collector never blocks the daemon.
//
// Every Publish stamps the envelope with a per-boot sequence number. The
// collector uses (boot, seq) for gap detection: a delivery lost to the
// backlog cap, a dead collector, or a restart leaves a visible hole instead
// of silently vanishing — lossy delivery must be *honest* loss.
type Publisher struct {
	mu      sync.Mutex
	sinks   []*Sink
	wg      sync.WaitGroup
	sem     chan struct{}
	dropped atomic.Uint64
	seq     atomic.Uint64
	boot    string
}

func NewPublisher() *Publisher {
	return &Publisher{sem: make(chan struct{}, maxInFlightDeliveries), boot: newBootID()}
}

// newBootID identifies one daemon run to the collector's gap detection.
// Random (not a persisted counter): a restart must look like a NEW boot so
// the collector resets its sequence expectation instead of flagging the
// reset itself as a gap.
func newBootID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// BootID exposes this run's boot identifier (tests, diagnostics).
func (p *Publisher) BootID() string { return p.boot }

// AddSink registers a sink (nil is ignored — disabled config entries).
func (p *Publisher) AddSink(s *Sink) {
	if s == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sinks = append(p.sinks, s)
}

// ReplaceSinks swaps the whole sink set atomically — the config hot-reload
// path rebuilds sinks from the new fleet section and swaps them in without
// disturbing in-flight deliveries (old sinks finish their HTTP attempts;
// only new Publishes route to the new set).
func (p *Publisher) ReplaceSinks(sinks []*Sink) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sinks = sinks
}

// HasSinks reports whether any sink is registered — callers use it to skip
// starting fleet-only machinery (the heartbeat loop) on unfleeted nodes.
func (p *Publisher) HasSinks() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sinks) > 0
}

// Publish delivers payload to every sink subscribed to kind, stamped with the
// next per-boot sequence number (shared across kinds — gaps are about the
// node's delivery stream, not per-kind streams). In-flight deliveries are
// capped; beyond the cap the event is dropped (counted, logged periodically)
// so a dead collector plus a flag storm cannot OOM the daemon. A drop DOES
// leave a sequence gap at the collector — that is the point.
func (p *Publisher) Publish(kind EventKind, payload any) {
	p.mu.Lock()
	sinks := append([]*Sink(nil), p.sinks...)
	p.mu.Unlock()
	if len(sinks) == 0 {
		return
	}
	seq := p.seq.Add(1)
	for _, s := range sinks {
		if !s.Subscribed(kind) {
			continue
		}
		select {
		case p.sem <- struct{}{}:
		default:
			if n := p.dropped.Add(1); n == 1 || n%100 == 0 {
				log.Printf("fleet: delivery backlog full (%d in flight); dropped %d deliveries so far", maxInFlightDeliveries, n)
			}
			continue
		}
		p.wg.Add(1)
		go func(s *Sink) {
			defer p.wg.Done()
			defer func() { <-p.sem }()
			s.Deliver(kind, payload, seq, p.boot)
		}(s)
	}
}

// Wait blocks until all in-flight deliveries settle (used at shutdown).
func (p *Publisher) Wait() { p.wg.Wait() }

// PublishGuardDecision satisfies api.GuardEventSink without an import cycle:
// the api package depends only on this narrow method, not on fleet.
func (p *Publisher) PublishGuardDecision(decision map[string]any) {
	p.Publish(EventGuard, decision)
}
