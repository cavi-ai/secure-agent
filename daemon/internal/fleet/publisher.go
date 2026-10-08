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
const maxTraceDeliveries = 48

// A slow sink cannot occupy all delivery slots. Within each sink, telemetry
// also leaves slots reserved for security decisions and liveness.
type sinkDeliveryState struct {
	seq         atomic.Uint64
	sem, traces chan struct{}
	boot        string
}

func newSinkDeliveryState() *sinkDeliveryState {
	return &sinkDeliveryState{sem: make(chan struct{}, 32), traces: make(chan struct{}, 24)}
}

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
	traces  chan struct{}
	started bool
	dropped atomic.Uint64
	boot    string
}

func NewPublisher() *Publisher {
	return &Publisher{sem: make(chan struct{}, maxInFlightDeliveries), traces: make(chan struct{}, maxTraceDeliveries), boot: newBootID()}
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
	p.bindSink(s, p.sinks)
	p.sinks = append(p.sinks, s)
}

// ReplaceSinks swaps the whole sink set atomically — the config hot-reload
// path rebuilds sinks from the new fleet section and swaps them in without
// disturbing in-flight deliveries (old sinks finish their HTTP attempts;
// only new Publishes route to the new set).
func (p *Publisher) ReplaceSinks(sinks []*Sink) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.sinks
	p.sinks = nil
	for _, s := range sinks {
		if s == nil {
			continue
		}
		p.bindSink(s, append(old, p.sinks...))
		p.sinks = append(p.sinks, s)
	}
}

func (p *Publisher) bindSink(s *Sink, existing []*Sink) {
	for _, prior := range existing {
		if prior.url == s.url && prior.nodeID == s.nodeID {
			s.state = prior.state
			return
		}
	}
	s.state.boot = p.boot
	// Re-enrollment is a new stream. Never reset a sequence within the old
	// epoch; the collector must be able to distinguish its late deliveries.
	if p.started {
		s.state.boot = newBootID()
	}
}

// HasSinks reports whether any sink is registered — callers use it to skip
// starting fleet-only machinery (the heartbeat loop) on unfleeted nodes.
func (p *Publisher) HasSinks() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sinks) > 0
}

// Publish delivers payload to every sink subscribed to kind, stamped with
// that sink's next per-boot sequence number. In-flight deliveries are capped;
// beyond the cap the event is dropped (counted, logged periodically) so a
// dead collector plus a flag storm cannot OOM the daemon. A drop DOES leave a
// sequence gap at that collector — that is the point. Sequence is per-sink
// because sinks subscribe to different kind sets: a kind one collector never
// receives must not advance its counter and fabricate a gap.
func (p *Publisher) Publish(kind EventKind, payload any) {
	p.mu.Lock()
	p.started = true
	sinks := append([]*Sink(nil), p.sinks...)
	p.mu.Unlock()
	for _, s := range sinks {
		if !s.Subscribed(kind) {
			continue
		}
		seq := s.NextSeq()
		release, ok := p.admit(s, kind)
		if !ok {
			if n := p.dropped.Add(1); n == 1 || n%100 == 0 {
				log.Printf("fleet: delivery backlog full (%d in flight); dropped %d deliveries so far", maxInFlightDeliveries, n)
			}
			continue
		}
		p.wg.Add(1)
		go func(s *Sink, seq uint64) {
			defer p.wg.Done()
			defer release()
			s.Deliver(kind, payload, seq, s.state.boot)
		}(s, seq)
	}
}

func (p *Publisher) admit(s *Sink, kind EventKind) (func(), bool) {
	channels := []chan struct{}{s.state.sem, p.sem}
	if kind == EventTrace || kind == EventSession {
		channels = append([]chan struct{}{s.state.traces, p.traces}, channels...)
	}
	for i, ch := range channels {
		select {
		case ch <- struct{}{}:
		default:
			for _, acquired := range channels[:i] {
				<-acquired
			}
			return nil, false
		}
	}
	return func() {
		for _, ch := range channels {
			<-ch
		}
	}, true
}

// Wait blocks until all in-flight deliveries settle (used at shutdown).
func (p *Publisher) Wait() { p.wg.Wait() }

// PublishGuardDecision satisfies api.GuardEventSink without an import cycle:
// the api package depends only on this narrow method, not on fleet.
func (p *Publisher) PublishGuardDecision(decision map[string]any) {
	p.Publish(EventGuard, decision)
}
