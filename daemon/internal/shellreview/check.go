package shellreview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Decision is a one-request check result. It never creates a standing permission.
type Decision struct {
	Mode          string `json:"mode"`
	Verdict       string `json:"verdict"`
	Reason        string `json:"reason,omitempty"`
	RequestDigest string `json:"request_digest"`
	ObservationID string `json:"observation_id,omitempty"`
}
type reviewJob struct {
	request Request
	ctx     context.Context
	reply   chan checkOutcome
}
type checkOutcome struct {
	result Result
	err    error
}

// Digest binds the reply to the submitted command and working directory.
func (r Request) Digest() string {
	digest := sha256.Sum256([]byte(r.Command + "\x00" + r.Cwd))
	return hex.EncodeToString(digest[:])
}

func decisionFor(r Result) Decision {
	d := Decision{Mode: "block", Verdict: "deny", ObservationID: r.ID, Reason: r.Reason}
	if r.GuardVerdict == "deny" {
		d.Reason = "existing_denial"
		return d
	}
	if r.Choice == "routine" && r.Reason == "" && !r.EvidenceRedacted {
		d.Verdict = "allow"
		return d
	}
	if d.Reason == "" {
		d.Reason = "model_" + r.Choice
	}
	return d
}

// Check may only add a denial to the hook's existing decision. It has no cache,
// and its total deadline includes queue wait, inference, and receipt storage.
func (s *Service) Check(parent context.Context, r Request) (decision Decision, err error) {
	if s == nil || s.cfg.Mode != "block" {
		return Decision{}, ErrDisabled
	}
	decision = Decision{Mode: "block", Verdict: "deny", RequestDigest: r.Digest()}
	defer func() {
		s.mu.Lock()
		s.health.Checks++
		if decision.Verdict != "allow" {
			s.health.Denied++
		}
		s.mu.Unlock()
	}()
	if err := r.Validate(); err != nil {
		return decision, err
	}
	if r.GuardVerdict == "deny" {
		decision.Reason = "existing_denial"
		return decision, nil
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(s.cfg.TimeoutMS)*time.Millisecond+200*time.Millisecond)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if ctx.Err() != nil {
		decision.Reason = "deadline"
		return decision, nil
	}
	reply := make(chan checkOutcome, 1)
	if err := s.enqueue(reviewJob{request: r, ctx: ctx, reply: reply}); err != nil {
		return decision, err
	}
	select {
	case outcome := <-reply:
		if ctx.Err() != nil {
			decision.Reason = "deadline"
			return decision, nil
		}
		if outcome.err != nil {
			decision.Reason = "receipt_unavailable"
			return decision, nil
		}
		decision = decisionFor(outcome.result)
		decision.RequestDigest = r.Digest()
		return decision, nil
	case <-ctx.Done():
		decision.Reason = "deadline"
		return decision, nil
	}
}
