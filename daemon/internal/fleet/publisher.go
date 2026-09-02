// Package fleet — delivery fan-out: subscribers register per-kind sinks, and
// the daemon's drain loop calls Publish for each flag/incident/guard decision.
package fleet

import (
	"sync"
)

// Publisher fans an event payload out to every subscribed sink. Delivery is
// asynchronous and best-effort: a dead collector never blocks the daemon.
type Publisher struct {
	mu    sync.Mutex
	sinks []*Sink
	wg    sync.WaitGroup
}

func NewPublisher() *Publisher { return &Publisher{} }

// AddSink registers a sink (nil is ignored — disabled config entries).
func (p *Publisher) AddSink(s *Sink) {
	if s == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sinks = append(p.sinks, s)
}

// Publish delivers payload to every sink subscribed to kind, one goroutine per
// sink per event, bounded by each sink's own HTTP timeout + retry budget.
func (p *Publisher) Publish(kind EventKind, payload any) {
	p.mu.Lock()
	sinks := append([]*Sink(nil), p.sinks...)
	p.mu.Unlock()
	for _, s := range sinks {
		if !s.Subscribed(kind) {
			continue
		}
		p.wg.Add(1)
		go func(s *Sink) {
			defer p.wg.Done()
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
