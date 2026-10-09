package guard

import (
	"context"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
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
	ID              string              `json:"id"`
	SessionID       string              `json:"session_id,omitempty"`
	Agent           string              `json:"agent"`
	Tool            string              `json:"tool"`
	Path            string              `json:"path"`
	RuleID          string              `json:"rule_id"`
	Workspace       string              `json:"workspace,omitempty"`
	ReaderExe       string              `json:"reader_exe,omitempty"`
	IdentityBasis   string              `json:"identity_basis,omitempty"`
	AvailableScopes []model.ScopeChoice `json:"available_scopes,omitempty"`
	PeerPID         int32               `json:"-"`
	TS              string              `json:"ts"`
	// ScopeText tells the user what an "allow always" would cover, so the
	// prompt discloses its blast radius instead of leaving it implied.
	ScopeText string `json:"scope_text,omitempty"`
	// Advisor is the local advisor's recommendation, attached when one has
	// landed. Advisory only: it never resolves the prompt; the human decides.
	// (Populated by the API when serving /guard/pending, not by the broker.)
	Advisor *model.AdvisorVerdict `json:"advisor,omitempty"`
}

type waiter struct {
	p         Pending
	chs       []chan Decision // one reply channel per blocked request, fanned out on resolve
	callers   map[chan Decision]pendingCaller
	resolved  bool
	preparing bool
}

type pendingCaller struct {
	p        Pending
	ctx      context.Context
	deadline time.Time
}

// key identifies an in-flight prompt by its semantic coordinates, so a second
// identical request shares the first one's waiter instead of stacking a
// duplicate dialog.
func dedupKey(p Pending) string {
	return p.SessionID + "\x00" + p.Agent + "\x00" + p.RuleID + "\x00" + p.Path + "\x00" + p.Tool + "\x00" + p.Workspace + "\x00" + p.ReaderExe + "\x00" + p.IdentityBasis
}

// Broker bridges a blocked hook request to an async user decision made in the
// menubar. Request() blocks until Resolve() or the timeout; the timeout returns
// a deny so a stalled/absent UI is fail-safe, never fail-open.
type Broker struct {
	mu      sync.Mutex
	waiters map[string]*waiter // by id
	byKey   map[string]string  // dedupKey -> id
	queue   []string           // ids in arrival order
	timeout time.Duration
}

func NewBroker(timeout time.Duration) *Broker {
	return &Broker{
		waiters: map[string]*waiter{},
		byKey:   map[string]string{},
		timeout: timeout,
	}
}

// Request registers a pending prompt and blocks for the decision, the timeout,
// or ctx ending (the hook stopped waiting). Identical in-flight requests (same
// agent/rule/path/tool) block on the same waiter so one resolution answers
// all of them; the prompt stays pending while any of them still waits. When
// the queue is full the request is denied immediately with an explicit
// reason.
func (b *Broker) Request(ctx context.Context, p Pending) Decision {
	if p.TS == "" {
		p.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b.mu.Lock()
	if len(b.waiters) >= MaxWaiters {
		b.mu.Unlock()
		return Decision{Verdict: "deny", Scope: "once", Reason: "queue-full"}
	}
	key := dedupKey(p)
	id, joined := b.byKey[key]
	ch := make(chan Decision, 1)
	deadline := time.Now().Add(b.timeout)
	if at, ok := ctx.Deadline(); ok && at.Before(deadline) {
		deadline = at
	}
	if joined {
		// Wait on the existing waiter's fan-out; this request adds no new prompt.
		b.waiters[id].chs = append(b.waiters[id].chs, ch)
	} else {
		id = p.ID
		b.waiters[id] = &waiter{p: p, chs: []chan Decision{ch}, callers: map[chan Decision]pendingCaller{}}
		b.byKey[key] = id
		b.queue = append(b.queue, id)
	}
	b.waiters[id].callers[ch] = pendingCaller{p: p, ctx: ctx, deadline: deadline}
	b.mu.Unlock()
	defer b.leave(id, ch)

	timer := time.NewTimer(b.timeout)
	defer timer.Stop()
	select {
	case d := <-ch:
		return d
	case <-timer.C:
		// A commit linearized before the deadline may have filled ch while
		// the timer became runnable. Prefer that committed decision.
		select {
		case d := <-ch:
			return d
		default:
		}
		return Decision{Verdict: "deny", Scope: "once", Reason: "timeout"}
	case <-ctx.Done():
		return Decision{Verdict: "deny", Scope: "once", Reason: "withdrawn"}
	}
}

// leave drops one request's reply channel and withdraws the prompt once no
// request is left waiting on it.
func (b *Broker) leave(id string, ch chan Decision) {
	b.mu.Lock()
	defer b.mu.Unlock()
	w, ok := b.waiters[id]
	if !ok {
		return
	}
	for i, c := range w.chs {
		if c == ch {
			w.chs = append(w.chs[:i], w.chs[i+1:]...)
			break
		}
	}
	delete(w.callers, ch)
	if len(w.chs) > 0 {
		return
	}
	delete(b.waiters, id)
	if b.byKey[dedupKey(w.p)] == id {
		delete(b.byKey, dedupKey(w.p))
	}
	for i, qid := range b.queue {
		if qid == id {
			b.queue = append(b.queue[:i], b.queue[i+1:]...)
			break
		}
	}
}

// Pending returns the queued prompts oldest-first, so the menubar always
// presents the longest-waiting request.
func (b *Broker) Pending() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Pending, 0, len(b.queue))
	for _, id := range b.queue {
		if w, ok := b.waiters[id]; ok && !w.resolved {
			out = append(out, w.p)
		}
	}
	return out
}

// Resolve delivers a decision to the waiter registered under id, fanned out to
// every duplicate request blocked on the same waiter. It returns false when no
// request is waiting on id any more.
func (b *Broker) Resolve(id string, d Decision) bool {
	ok, _ := b.ResolveWith(id, d, nil)
	return ok
}

// ResolveWith prepares durable state without holding the broker lock. After
// preparation, the original waiter and deadline are checked again; commit
// and delivery share one linearization point. Expired preparations roll back.
func (b *Broker) ResolveWith(id string, d Decision, prepare func(context.Context, Pending) (func() error, func(), error)) (bool, error) {
	b.mu.Lock()
	w, ok := b.waiters[id]
	if !ok || w.resolved || w.preparing {
		b.mu.Unlock()
		return false, nil
	}
	selected := pendingCaller{p: w.p, ctx: context.Background(), deadline: time.Now().Add(b.timeout)}
	if prepare != nil {
		selected.ctx = nil
		for _, c := range w.callers {
			if c.ctx.Err() == nil && time.Now().Before(c.deadline) && (selected.ctx == nil || c.deadline.After(selected.deadline)) {
				selected = c
			}
		}
		if selected.ctx == nil {
			b.mu.Unlock()
			return false, nil
		}
		selected.p.ID = w.p.ID
	}
	w.preparing = true
	b.mu.Unlock()
	ctx, cancel := context.WithDeadline(selected.ctx, selected.deadline)
	defer cancel()
	var commit func() error
	if prepare != nil {
		var rollback func()
		var err error
		commit, rollback, err = prepare(ctx, selected.p)
		if rollback != nil {
			defer rollback()
		}
		if err != nil {
			b.mu.Lock()
			w.preparing = false
			b.mu.Unlock()
			return false, err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w.preparing = false
	if b.waiters[id] != w || w.resolved || (prepare != nil && (ctx.Err() != nil || !time.Now().Before(selected.deadline))) {
		return false, nil
	}
	if commit != nil {
		if err := commit(); err != nil {
			return false, err
		}
	}
	w.resolved = true
	delete(b.byKey, dedupKey(w.p))
	delivered := false
	// Sends are non-blocking (channels are buffered cap-1, senders select with
	// default), so holding the lock here is safe — and required: Request()
	// appends to w.chs under the same mutex, so iterating it unlocked is a
	// data race.
	for _, ch := range w.chs {
		select {
		case ch <- d:
			delivered = true
		default:
		}
	}
	return delivered, nil
}
