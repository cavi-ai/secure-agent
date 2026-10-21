// Package localmodel bounds inference across the daemon's local AI consumers.
package localmodel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const ContextTokens = 32768
const MaxQueued = 16

var ErrPaused = errors.New("background model review is paused")
var ErrQueueFull = errors.New("local model queue is full")
var ErrBudget = errors.New("background review used its two-minute budget; available again after the fifteen-minute window")

// Default coordinates all inference performed by this daemon, not other apps.
var Default = New()

type Status struct {
	BackgroundRemainingMS int64     `json:"background_remaining_ms"`
	BackgroundRetryAt     time.Time `json:"background_retry_at,omitzero"`
	Active                bool      `json:"active"`
	Foreground            bool      `json:"foreground"`
	Queued                int       `json:"queued"`
	BackgroundPaused      bool      `json:"background_paused"`
	ElapsedMS             int64     `json:"elapsed_ms"`
	ContextTokens         int       `json:"context_tokens"`
	IdleSeconds           int       `json:"idle_seconds"`
	Scope                 string    `json:"scope"`
}
type waiter struct {
	ctx        context.Context
	cancel     context.CancelFunc
	foreground bool
	ready      chan error
}
type Pool struct {
	windowStarted  time.Time
	backgroundUsed time.Duration
	nextCall       atomic.Uint64
	mu             sync.Mutex
	current        *waiter
	started        time.Time
	queue          []*waiter
	paused         bool
}
type priorityKey struct{}

func Foreground(ctx context.Context) context.Context {
	return context.WithValue(ctx, priorityKey{}, true)
}
func Background(ctx context.Context) context.Context {
	return context.WithValue(ctx, priorityKey{}, false)
}

func New() *Pool { return &Pool{} }
func (p *Pool) Snapshot() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Status{Active: p.current != nil, Queued: len(p.queue), BackgroundPaused: p.paused, ContextTokens: ContextTokens, IdleSeconds: 120, Scope: "daemon requests; external server use is not controlled"}
	remaining := p.backgroundRemainingLocked()
	s.BackgroundRemainingMS = remaining.Milliseconds()
	if remaining <= 0 {
		s.BackgroundRetryAt = p.windowStarted.Add(15 * time.Minute)
	}
	if p.current != nil {
		s.Foreground = p.current.foreground
		s.ElapsedMS = time.Since(p.started).Milliseconds()
	}
	return s
}
func (p *Pool) backgroundRemainingLocked() time.Duration {
	if p.windowStarted.IsZero() || time.Since(p.windowStarted) >= 15*time.Minute {
		p.windowStarted = time.Now()
		p.backgroundUsed = 0
	}
	used := p.backgroundUsed
	if p.current != nil && !p.current.foreground {
		used += time.Since(p.started)
	}
	return max(0, 2*time.Minute-used)
}
func (p *Pool) PauseBackground(paused bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = paused
	if paused {
		if p.current != nil && !p.current.foreground {
			p.current.cancel()
		}
		kept := p.queue[:0]
		for _, w := range p.queue {
			if !w.foreground {
				w.ready <- ErrPaused
			} else {
				kept = append(kept, w)
			}
		}
		p.queue = kept
	}
}
func (p *Pool) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current != nil {
		p.current.cancel()
	}
}
func (p *Pool) acquire(w *waiter) error {
	p.mu.Lock()
	if !w.foreground && p.backgroundRemainingLocked() <= 0 {
		p.mu.Unlock()
		return ErrBudget
	}
	if !w.foreground && p.paused {
		p.mu.Unlock()
		return ErrPaused
	}
	if p.current == nil {
		p.current = w
		p.started = time.Now()
		p.mu.Unlock()
		return nil
	}
	if len(p.queue) >= MaxQueued {
		p.mu.Unlock()
		return ErrQueueFull
	}
	p.queue = append(p.queue, w)
	p.mu.Unlock()
	select {
	case err := <-w.ready:
		return err
	case <-w.ctx.Done():
		p.mu.Lock()
		for i, q := range p.queue {
			if q == w {
				p.queue = append(p.queue[:i], p.queue[i+1:]...)
				break
			}
		}
		granted := p.current == w
		p.mu.Unlock()
		if granted {
			p.release(w)
		}
		return w.ctx.Err()
	}
}
func (p *Pool) release(w *waiter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current != w {
		return
	}
	if !w.foreground {
		p.backgroundUsed += time.Since(p.started)
	}
	p.current = nil
	for len(p.queue) > 0 {
		i := 0
		for j, q := range p.queue {
			if q.foreground {
				i = j
				break
			}
		}
		next := p.queue[i]
		p.queue = append(p.queue[:i], p.queue[i+1:]...)
		if next.ctx.Err() != nil {
			continue
		}
		if !next.foreground && p.backgroundRemainingLocked() <= 0 {
			next.ready <- ErrBudget
			continue
		}
		p.current = next
		p.started = time.Now()
		next.ready <- nil
		break
	}
}

type transport struct {
	pool       *Pool
	base       http.RoundTripper
	foreground bool
	native     bool
}

func (p *Pool) Transport(base http.RoundTripper, foreground bool) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{pool: p, base: base, foreground: foreground}
}
func (p *Pool) OllamaTransport(base http.RoundTripper, foreground bool) http.RoundTripper {
	t := p.Transport(base, foreground).(*transport)
	t.native = true
	return t
}

type responseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *responseBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.release); return err }
func (b *responseBody) Read(v []byte) (int, error) {
	n, err := b.ReadCloser.Read(v)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v1/chat/completions" {
		return t.base.RoundTrip(req)
	}
	ctx, cancel := context.WithCancel(req.Context())
	w := &waiter{ctx: ctx, cancel: cancel, foreground: t.foreground, ready: make(chan error, 1)}
	if foreground, ok := ctx.Value(priorityKey{}).(bool); ok {
		w.foreground = foreground
	}
	if err := t.pool.acquire(w); err != nil {
		cancel()
		return nil, err
	}
	budgetCancel := func() {}
	if !w.foreground {
		t.pool.mu.Lock()
		remaining := t.pool.backgroundRemainingLocked()
		t.pool.mu.Unlock()
		ctx, budgetCancel = context.WithTimeoutCause(ctx, remaining, ErrBudget)
	}
	release := func() { budgetCancel(); cancel(); t.pool.release(w) }
	resp, err := t.infer(req.Clone(ctx))
	if err != nil {
		if errors.Is(context.Cause(ctx), ErrBudget) {
			err = ErrBudget
		}
		release()
		return nil, err
	}
	resp.Body = &responseBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}
