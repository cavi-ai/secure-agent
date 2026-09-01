package supervise

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Defaults for a Supervisor created with New.
const (
	// defaultMinHealthy is how long a worker must run before a failure is treated
	// as transient: a run lasting at least this long resets the backoff and the
	// continuous-failure clock.
	defaultMinHealthy = 30 * time.Second
	// defaultMaxBackoff caps the restart delay so a permanently-failing worker
	// retries at most this often — cheap enough to keep trying indefinitely
	// without spinning the CPU or spamming the log.
	defaultMaxBackoff = 30 * time.Second
	// defaultAbandonAfter is how long a worker may fail *continuously* before the
	// supervisor stops restarting it and marks it abandoned. It is deliberately
	// minutes, not seconds: a boot-time transient (a listen port still in
	// TIME_WAIT from a prior instance, an Endpoint Security entitlement not yet
	// granted at login) must never permanently disable a collector for the
	// session. Only sustained failure past this window is treated as permanent.
	defaultAbandonAfter = 3 * time.Minute
)

// Health is the observable state of one supervised worker. It is surfaced through
// the control API so a dead or abandoned collector cannot masquerade as healthy.
type Health struct {
	Name      string `json:"name"`
	Running   bool   `json:"running"`
	Abandoned bool   `json:"abandoned"`
	Restarts  int    `json:"restarts"`
	LastError string `json:"last_error,omitempty"`
}

// Registry is a concurrency-safe collection of worker health, updated by the
// supervisor and read by the status endpoint. The zero value is not usable; call
// NewRegistry. A nil *Registry is accepted everywhere and simply records nothing.
type Registry struct {
	mu sync.Mutex
	m  map[string]Health
}

func NewRegistry() *Registry {
	return &Registry{m: make(map[string]Health)}
}

func (r *Registry) update(name string, mut func(*Health)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.m[name]
	h.Name = name
	mut(&h)
	r.m[name] = h
}

// Snapshot returns a copy of every tracked worker's health.
func (r *Registry) Snapshot() []Health {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Health, 0, len(r.m))
	for _, h := range r.m {
		out = append(out, h)
	}
	return out
}

// Supervisor restarts workers with capped exponential backoff and records their
// health. It never abandons a worker for a short-lived failure; see AbandonAfter.
type Supervisor struct {
	reg          *Registry
	MinHealthy   time.Duration
	MaxBackoff   time.Duration
	AbandonAfter time.Duration // continuous-failure duration before giving up; 0 = never give up
}

// New returns a Supervisor with production defaults. reg may be nil.
func New(reg *Registry) *Supervisor {
	return &Supervisor{
		reg:          reg,
		MinHealthy:   defaultMinHealthy,
		MaxBackoff:   defaultMaxBackoff,
		AbandonAfter: defaultAbandonAfter,
	}
}

// Run supervises fn under ctx. On every non-nil return (or panic) it restarts fn
// with capped exponential backoff. A run that stays healthy for MinHealthy resets
// the backoff and the continuous-failure clock. Only after AbandonAfter of
// *continuous* failure (0 = never) does it stop and mark the worker abandoned.
// Returns when ctx is cancelled or the worker is abandoned.
func (s *Supervisor) Run(ctx context.Context, name string, fn func(context.Context) error) {
	backoff := 100 * time.Millisecond
	restarts := 0
	var firstFailure time.Time // zero until the current failure streak began

	for {
		if ctx.Err() != nil {
			return
		}

		s.reg.update(name, func(h *Health) { h.Running = true; h.Abandoned = false })
		start := time.Now()
		err := runOnce(ctx, fn)

		if ctx.Err() != nil {
			s.reg.update(name, func(h *Health) { h.Running = false })
			return
		}

		if time.Since(start) >= s.MinHealthy {
			// Long healthy run: this exit is a transient blip, not a failure streak.
			backoff = 100 * time.Millisecond
			firstFailure = time.Time{}
		}

		if err == nil {
			// Clean exit without ctx cancel: nothing to restart for.
			s.reg.update(name, func(h *Health) { h.Running = false })
			return
		}

		restarts++
		if firstFailure.IsZero() {
			firstFailure = start
		}
		errStr := err.Error()
		s.reg.update(name, func(h *Health) {
			h.Running = false
			h.Restarts = restarts
			h.LastError = errStr
		})

		if s.AbandonAfter > 0 && time.Since(firstFailure) >= s.AbandonAfter {
			log.Printf("supervisor: worker %s failed continuously for %v; abandoning (last error: %v)", name, s.AbandonAfter, err)
			s.reg.update(name, func(h *Health) { h.Abandoned = true })
			return
		}

		log.Printf("supervisor: worker %s exited: %v (restart #%d in %v)", name, err, restarts, backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		if backoff < s.MaxBackoff {
			backoff *= 2
			if backoff > s.MaxBackoff {
				backoff = s.MaxBackoff
			}
		}
	}
}

// runOnce runs fn and converts a panic into an error so one worker's panic
// cannot crash the whole daemon; the supervisor restarts it like any error.
func runOnce(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(ctx)
}

// Run is the untracked, default-tuned convenience wrapper.
func Run(ctx context.Context, name string, fn func(context.Context) error) {
	New(nil).Run(ctx, name, fn)
}
