// Package shellreview provides bounded local shell risk observations and checks.
package shellreview

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
)

const MaxCommandBytes = 8192
const minimumRoutineProbability = 0.9

var ErrQueueFull = errors.New("shell review queue full")
var ErrDisabled = errors.New("shell review disabled")

type Config struct {
	Enabled   bool   `yaml:"enabled"`
	Mode      string `yaml:"mode"`
	Endpoint  string `yaml:"endpoint"`
	Model     string `yaml:"model"`
	TimeoutMS int    `yaml:"timeout_ms"`
}

func (c Config) Validate() error {
	if c.Mode != "" && c.Mode != "observe" && c.Mode != "block" {
		return errors.New("directory_guard.shell_review.mode must be observe or block")
	}
	if (c.Enabled || c.Endpoint != "") && !loopback.ValidEndpoint(c.Endpoint) {
		return errors.New("directory_guard.shell_review.endpoint must be loopback")
	}
	if c.TimeoutMS < 0 || c.TimeoutMS > 5000 {
		return errors.New("directory_guard.shell_review.timeout_ms must be between 0 and 5000")
	}
	if len(c.Model) > 128 || strings.ContainsAny(c.Model, "\x00\r\n") {
		return errors.New("invalid shell review model")
	}
	return nil
}

// Request contains hook-reported facts, never trusted user authorization.
// Commands are held only in the bounded queue and never persisted.
type Request struct {
	Command      string `json:"command"`
	Cwd          string `json:"cwd"`
	SessionID    string `json:"session_id"`
	CallID       string `json:"call_id"`
	GuardVerdict string `json:"guard_verdict"`
}

func (r Request) Validate() error {
	if r.Command == "" || len(r.Command) > MaxCommandBytes || !utf8.ValidString(r.Command) ||
		len(r.Cwd) > 4096 || !utf8.ValidString(r.Cwd) || len(r.SessionID) > 256 || len(r.CallID) > 256 ||
		(r.GuardVerdict != "allow" && r.GuardVerdict != "deny") {
		return errors.New("invalid shell observation")
	}
	if strings.ContainsRune(r.Command, 0) || strings.ContainsRune(r.Cwd, 0) {
		return errors.New("invalid shell observation")
	}
	return nil
}

// Result is an observation, not an approval or evidence that a command ran.
// It deliberately carries no command, working directory, or model-generated prose.
type Result struct {
	ID               string             `json:"id"`
	At               time.Time          `json:"at"`
	Mode             string             `json:"mode"`
	PolicyVersion    string             `json:"policy_version"`
	Calibration      string             `json:"calibration"`
	Model            string             `json:"model"`
	SessionID        string             `json:"session_id,omitempty"`
	CallID           string             `json:"call_id,omitempty"`
	IdentityBasis    string             `json:"identity_basis"`
	CommandDigest    string             `json:"command_digest,omitempty"`
	RequestDigest    string             `json:"request_digest,omitempty"`
	EvidenceRedacted bool               `json:"evidence_redacted"`
	GuardVerdict     string             `json:"guard_verdict"`
	Choice           string             `json:"choice"`
	ModelChoice      string             `json:"model_choice,omitempty"`
	Confidence       float64            `json:"confidence"`
	Probabilities    map[string]float64 `json:"probabilities,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	ProposedVerdict  string             `json:"proposed_verdict,omitempty"`
	DurationMS       int64              `json:"duration_ms"`
}

type Health struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	Pending       int    `json:"pending"`
	Active        bool   `json:"active"`
	Completed     uint64 `json:"completed"`
	Dropped       uint64 `json:"dropped"`
	Unavailable   uint64 `json:"unavailable"`
	Abstained     uint64 `json:"abstained"`
	WriteFailures uint64 `json:"write_failures"`
	Checks        uint64 `json:"checks"`
	Denied        uint64 `json:"denied"`
}

type Service struct {
	cfg    Config
	mask   func(string) (string, bool)
	save   func(Result) error
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	queue  chan reviewJob
	mu     sync.Mutex
	closed bool
	health Health
}

func New(ctx context.Context, cfg Config, mask func(string) (string, bool), save func(Result) error) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}
	if mask == nil || save == nil {
		return nil, errors.New("shell review needs masking and persistence")
	}
	if cfg.Model == "" {
		cfg.Model = "kev-latest"
	}
	if cfg.Mode == "" {
		cfg.Mode = "observe"
	}
	if cfg.TimeoutMS == 0 {
		cfg.TimeoutMS = 1000
	}
	life, cancel := context.WithCancel(ctx)
	s := &Service{cfg: cfg, mask: mask, save: save, ctx: life, cancel: cancel, done: make(chan struct{}), queue: make(chan reviewJob, 32), health: Health{Enabled: true, Mode: cfg.Mode}}
	go s.run()
	return s, nil
}

// Submit never waits for inference or storage. Rejection is visible to the hook.
func (s *Service) Submit(r Request) error {
	if s == nil {
		return ErrDisabled
	}
	return s.enqueue(reviewJob{request: r, ctx: s.ctx})
}

func (s *Service) enqueue(job reviewJob) error {
	if s == nil {
		return ErrDisabled
	}
	if err := job.request.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrDisabled
	}
	select {
	case s.queue <- job:
		return nil
	default:
		s.health.Dropped++
		return ErrQueueFull
	}
}

func (s *Service) Health() Health {
	if s == nil {
		return Health{Mode: "off"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.health
	h.Pending = len(s.queue)
	return h
}

func (s *Service) Close() {
	if s == nil {
		return
	}
	s.cancel()
	<-s.done
}

func (s *Service) run() {
	defer close(s.done)
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		s.health.Enabled = false
		s.health.Dropped += uint64(len(s.queue))
		for len(s.queue) > 0 {
			<-s.queue
		}
	}()
	for {
		if s.ctx.Err() != nil {
			return
		}
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.queue:
			s.mu.Lock()
			s.health.Active = true
			s.mu.Unlock()
			result := s.review(job.ctx, job.request)
			if job.reply != nil {
				result.Mode = "block"
				result.RequestDigest = job.request.Digest()
				result.ProposedVerdict = decisionFor(result).Verdict
			}
			err := s.save(result)
			if job.reply != nil {
				job.reply <- checkOutcome{result: result, err: err}
			}
			s.mu.Lock()
			s.health.Active = false
			s.health.Completed++
			if result.Choice == "unknown" {
				s.health.Abstained++
			}
			if result.Reason != "" && result.Reason != "uncertain_classification" && result.Reason != "evidence_redacted" {
				s.health.Unavailable++
			}
			if err != nil {
				s.health.WriteFailures++
			}
			s.mu.Unlock()
		}
	}
}

func (s *Service) review(ctx context.Context, req Request) (result Result) {
	start := time.Now()
	defer func() { result.DurationMS = time.Since(start).Milliseconds() }()
	id := make([]byte, 16)
	// crypto/rand.Read fills the entire slice or terminates on entropy failure.
	rand.Read(id)
	result = Result{ID: hex.EncodeToString(id), At: start.UTC(), Mode: "observe", PolicyVersion: policyVersion, Calibration: "unvalidated", Model: s.cfg.Model, IdentityBasis: "hook-reported", GuardVerdict: req.GuardVerdict, Choice: "unknown"}
	command, ok := s.mask(redact.Scrub(req.Command))
	cwd, cwdOK := s.mask(redact.Scrub(req.Cwd))
	session, sessionOK := s.mask(redact.Scrub(req.SessionID))
	call, callOK := s.mask(redact.Scrub(req.CallID))
	if !ok || !cwdOK || !sessionOK || !callOK {
		result.Reason = "redaction_failed"
		return result
	}
	result.SessionID, result.CallID = session, call
	result.EvidenceRedacted = command != req.Command || cwd != req.Cwd || strings.Contains(command, "[REDACTED") || strings.Contains(cwd, "[REDACTED")
	digest := sha256.Sum256([]byte(command))
	result.CommandDigest = fmt.Sprintf("%x", digest)
	if len(command) > MaxCommandBytes || len(cwd) > 4096 {
		result.Reason = "evidence_too_large"
		return result
	}
	answer, reason := s.classify(ctx, command, cwd)
	result.Reason = reason
	if reason == "" {
		result.Choice = answer.Choice
		result.ModelChoice = answer.Choice
		result.Confidence = *answer.Confidence
		result.Probabilities = make(map[string]float64, len(answer.Probabilities))
		for key, probability := range answer.Probabilities {
			result.Probabilities[key] = *probability
		}
	}
	if result.Choice == "routine" && result.EvidenceRedacted {
		result.Choice, result.Reason = "unknown", "evidence_redacted"
		result.Confidence, result.Probabilities = 0, nil
	}
	if result.Choice == "routine" && result.Probabilities["routine"] < minimumRoutineProbability {
		result.Choice, result.Reason = "unknown", "uncertain_classification"
	}
	return result
}
