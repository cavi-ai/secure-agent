// Package fleet — delivery fan-out: subscribers register per-kind sinks, and
// the daemon's drain loop calls Publish for each flag/incident/guard decision.
package fleet

import (
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
type Publisher struct {
	mu      sync.Mutex
	sinks   []*Sink
	wg      sync.WaitGroup
	sem     chan struct{}
	dropped atomic.Uint64
}

func NewPublisher() *Publisher {
	return &Publisher{sem: make(chan struct{}, maxInFlightDeliveries)}
}

// AddSink registers a sink (nil is ignored — disabled config entries).
func (p *Publisher) AddSink(s *Sink) {
	if s == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sinks = append(p.sinks, s)
}

// Publish delivers payload to every sink subscribed to kind. In-flight
// deliveries are capped; beyond the cap the event is dropped (counted, logged
// periodically) so a dead collector plus a flag storm cannot OOM the daemon.
func (p *Publisher) Publish(kind EventKind, payload any) {
	p.mu.Lock()
	sinks := append([]*Sink(nil), p.sinks...)
	p.mu.Unlock()
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
			s.Deliver(kind, payload)
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
