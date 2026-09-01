package guard

import (
	"sync"
	"time"
)

type Decision struct {
	Verdict string `json:"verdict"`
	Scope   string `json:"scope"`
	Reason  string `json:"reason,omitempty"`
}

type Pending struct {
	ID     string `json:"id"`
	Agent  string `json:"agent"`
	Tool   string `json:"tool"`
	Path   string `json:"path"`
	RuleID string `json:"rule_id"`
	TS     string `json:"ts"`
}

type waiter struct {
	p  Pending
	ch chan Decision
}

// Broker bridges a blocked hook request to an async user decision made in the
// menubar. Request() blocks until Resolve() or the timeout; the timeout returns
// a deny so a stalled/absent UI is fail-safe, never fail-open.
type Broker struct {
	mu      sync.Mutex
	waiters map[string]*waiter
	timeout time.Duration
}

func NewBroker(timeout time.Duration) *Broker {
	return &Broker{waiters: map[string]*waiter{}, timeout: timeout}
}

func (b *Broker) Request(p Pending) Decision {
	if p.TS == "" {
		p.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	ch := make(chan Decision, 1)
	b.mu.Lock()
	b.waiters[p.ID] = &waiter{p: p, ch: ch}
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.waiters, p.ID)
		b.mu.Unlock()
	}()

	select {
	case d := <-ch:
		return d
	case <-time.After(b.timeout):
		return Decision{Verdict: "deny", Scope: "once", Reason: "timeout"}
	}
}

func (b *Broker) Pending() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Pending, 0, len(b.waiters))
	for _, w := range b.waiters {
		out = append(out, w.p)
	}
	return out
}

func (b *Broker) Resolve(id string, d Decision) bool {
	b.mu.Lock()
	w, ok := b.waiters[id]
	b.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case w.ch <- d:
		return true
	default:
		return false
	}
}
