package api

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
)

// Automatic review: with system_agent.auto_review on, each new finding of
// severity 2 or more joins a batch the local agent reviews without a click.
// A burst is one review: the batch waits autoReviewDelay after its first
// finding. Reviews go out at least autoReviewGap apart and carry at most
// autoReviewBatch findings, so the local model is never flooded. A busy
// agent keeps the batch for the next attempt.
const (
	autoReviewDelay = 2 * time.Minute
	autoReviewGap   = 10 * time.Minute
	autoReviewBatch = 10
	// autoReviewSeen bounds the remembered flag ids (each is reviewed once).
	autoReviewSeen = 1000
)

type autoReviewer struct {
	mu      sync.Mutex
	pending []string
	seen    map[string]bool
	armed   bool      // a flush is scheduled
	last    time.Time // when the last review went out or was refused as busy
	now     func() time.Time
	// schedule runs f after d (time.AfterFunc; tests capture it).
	schedule func(d time.Duration, f func())
}

func newAutoReviewer() *autoReviewer {
	return &autoReviewer{
		seen:     map[string]bool{},
		now:      time.Now,
		schedule: func(d time.Duration, f func()) { time.AfterFunc(d, f) },
	}
}

// NoteNewFlag offers a newly raised flag for automatic review. Non-blocking;
// a no-op unless the agent is enabled with auto_review on.
func (a *API) NoteNewFlag(fl model.Flag) {
	if a.sysAgent == nil || a.autoReview == nil || fl.Severity < 2 || fl.Acknowledged || !a.sysAgent.AutoReview() {
		return
	}
	r := a.autoReview
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[fl.ID] {
		return
	}
	if len(r.seen) >= autoReviewSeen {
		r.seen = map[string]bool{}
	}
	r.seen[fl.ID] = true
	r.pending = append(r.pending, fl.ID)
	r.armLocked(autoReviewDelay, a.flushAutoReview)
}

// armLocked schedules flush after delay, and no sooner than autoReviewGap
// after the last review, unless one is scheduled or nothing is pending.
func (r *autoReviewer) armLocked(delay time.Duration, flush func()) {
	if r.armed || len(r.pending) == 0 {
		return
	}
	wait := delay
	if !r.last.IsZero() {
		if gap := r.last.Add(autoReviewGap).Sub(r.now()); gap > wait {
			wait = gap
		}
	}
	r.armed = true
	r.schedule(wait, flush)
}

// flushAutoReview sends the oldest pending findings that are still
// unacknowledged to the review queue, then arms the next batch.
func (a *API) flushAutoReview() {
	r := a.autoReview
	r.mu.Lock()
	r.armed = false
	ids := append([]string(nil), r.pending[:min(len(r.pending), autoReviewBatch)]...)
	r.pending = r.pending[len(ids):]
	r.mu.Unlock()

	var flags []model.Flag
	for _, id := range ids {
		if f, ok := a.store.GetFlagWithAdvisor(id); ok && !f.Acknowledged {
			flags = append(flags, f)
		}
	}
	tried := false
	if len(flags) > 0 && a.sysAgent.AutoReview() {
		tried = true
		prompt, carried := a.analysisPrompt(flags)
		if _, err := a.sysAgent.SendAnalysis("Automatic review of new findings.\n"+prompt, carried); err != nil {
			if errors.Is(err, sysagent.ErrBusy) {
				r.mu.Lock()
				r.pending = append(ids, r.pending...)
				r.mu.Unlock()
			} else {
				log.Printf("auto review: %v", err)
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if tried {
		r.last = r.now()
	}
	r.armLocked(0, a.flushAutoReview)
}
