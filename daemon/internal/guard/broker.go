package guard

import (
	"sync"
	"time"
)

// MaxWaiters bounds the pending-prompt queue. A misbehaving agent that loops
// on a prompt-mode path must not be able to pile up unbounded waiters (and
// unbounded menubar dialogs); overflow is refused with an explicit deny so
// the hook always gets an answer.
const MaxWaiters = 32

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
	// ScopeText tells the user what an "allow always" would cover, so the
	// prompt discloses its blast radius instead of leaving it implied.
	ScopeText string `json:"scope_text,omitempty"`
}

type waiter struct {
	p   Pending
	chs []chan Decision // one reply channel per blocked request, fanned out on resolve
}

// key identifies an in-flight prompt by its semantic coordinates, so a second
// identical request shares the first one's waiter instead of stacking a
// duplicate dialog.
func dedupKey(p Pending) string {
	return p.Agent + "\x00" + p.RuleID + "\x00" + p.Path + "\x00" + p.Tool
}

// Broker bridges a blocked hook request to an async user decision made in the
// menubar. Request() blocks until Resolve() or the timeout; the timeout returns
// a deny so a stalled/absent UI is fail-safe, never fail-open.
type Broker struct {
	mu      sync.Mutex
	waiters map[string]*waiter          // by id
	byKey   map[string]string           // dedupKey -> id
	queue   []string                    // ids in arrival order
	timeout time.Duration
}

func NewBroker(timeout time.Duration) *Broker {
	return &Broker{
		waiters: map[string]*waiter{},
		byKey:   map[string]string{},
		timeout: timeout,
	}
}

// Request registers a pending prompt and blocks for the decision. Identical
// in-flight requests (same agent/rule/path/tool) block on the same waiter so
// one resolution answers all of them. When the queue is full the request is
// denied immediately with an explicit reason.
func (b *Broker) Request(p Pending) Decision {
	if p.TS == "" {
		p.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b.mu.Lock()
	if len(b.waiters) >= MaxWaiters {
		b.mu.Unlock()
		return Decision{Verdict: "deny", Scope: "once", Reason: "queue-full"}
	}
	key := dedupKey(p)
	if id, ok := b.byKey[key]; ok {
		w := b.waiters[id]
		ch := make(chan Decision, 1)
		w.chs = append(w.chs, ch)
		b.mu.Unlock()
		// Wait on the existing waiter's fan-out; this request adds no new prompt.
		select {
		case d := <-ch:
			return d
		case <-time.After(b.timeout):
			return Decision{Verdict: "deny", Scope: "once", Reason: "timeout"}
		}
	}
	chs := []chan Decision{make(chan Decision, 1)}
	w := &waiter{p: p, chs: chs}
	b.waiters[p.ID] = w
	b.byKey[key] = p.ID
	b.queue = append(b.queue, p.ID)
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.waiters, p.ID)
		delete(b.byKey, key)
		for i, id := range b.queue {
			if id == p.ID {
				b.queue = append(b.queue[:i], b.queue[i+1:]...)
				break
			}
		}
		b.mu.Unlock()
	}()

	select {
	case d := <-chs[0]:
		return d
	case <-time.After(b.timeout):
		return Decision{Verdict: "deny", Scope: "once", Reason: "timeout"}
	}
}

// Pending returns the queued prompts oldest-first, so the menubar always
// presents the longest-waiting request.
func (b *Broker) Pending() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Pending, 0, len(b.queue))
	for _, id := range b.queue {
		if w, ok := b.waiters[id]; ok {
			out = append(out, w.p)
		}
	}
	return out
}

// Resolve delivers a decision to the waiter registered under id, fanned out to
// every duplicate request blocked on the same waiter.
func (b *Broker) Resolve(id string, d Decision) bool {
	b.mu.Lock()
	w, ok := b.waiters[id]
	b.mu.Unlock()
	if !ok {
		return false
	}
	delivered := false
	for _, ch := range w.chs {
		select {
		case ch <- d:
			delivered = true
		default:
		}
	}
	return delivered
}