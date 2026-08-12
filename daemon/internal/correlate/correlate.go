package correlate

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

type readMark struct {
	at   time.Time
	path string
	cat  sensitive.Category
}

const window = 60 * time.Second

type Correlator struct {
	mu         sync.Mutex
	tagger     *agents.Tagger
	classifier sensitive.Classifier
	cfg        config.Config
	marks      map[int32][]readMark
}

func New(tagger *agents.Tagger, classifier sensitive.Classifier, cfg config.Config) *Correlator {
	return &Correlator{
		tagger:     tagger,
		classifier: classifier,
		cfg:        cfg,
		marks:      make(map[int32][]readMark),
	}
}

func (c *Correlator) Observe(e event.Event) []model.Flag {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, isAgent := c.tagger.Tag(e.PID)
	if !isAgent {
		return nil
	}

	var flags []model.Flag

	switch e.Kind {
	case event.KindFileOpen, event.KindFileWrite:
		if cat, ok := c.classifier.Classify(e.Path); ok {
			if cat == sensitive.CatKeychain {
				// Rule 2: Keychain access flags immediately
				flagID := hashFlagID("keychain-access", e.PID, e.TS)
				evidence := []string{
					fmt.Sprintf("%s (pid %d) accessed keychain file %s at %s", info.Name, e.PID, e.Path, e.TS.Format(time.RFC3339)),
				}
				flags = append(flags, model.Flag{
					ID:       flagID,
					Rule:     "keychain-access",
					Severity: 2,
					TS:       e.TS,
					PID:      e.PID,
					Agent:    info.Name,
					Evidence: evidence,
				})
			} else {
				c.rememberLocked(e.PID, readMark{at: e.TS, path: e.Path, cat: cat})
			}
		}

	case event.KindConnOpen:
		recent := c.recentReadsLocked(e.PID, e.TS, window)
		if len(recent) == 0 {
			return nil
		}
		if c.isVendorHost(info.Name, e.RemoteHost) {
			return nil
		}

		// Rule 1: sensitive-read-then-connect
		flagID := hashFlagID("sensitive-read-then-connect", e.PID, recent[0].at)
		var evidence []string
		for _, m := range recent {
			evidence = append(evidence, fmt.Sprintf("%s (pid %d) read %s at %s", info.Name, e.PID, m.path, m.at.Format(time.RFC3339)))
		}
		evidence = append(evidence, fmt.Sprintf("then connected to %s:%d at %s", e.RemoteHost, e.RemotePort, e.TS.Format(time.RFC3339)))

		flags = append(flags, model.Flag{
			ID:       flagID,
			Rule:     "sensitive-read-then-connect",
			Severity: 3,
			TS:       e.TS,
			PID:      e.PID,
			Agent:    info.Name,
			Evidence: evidence,
		})
	}

	return flags
}

func (c *Correlator) rememberLocked(pid int32, rm readMark) {
	list := c.marks[pid]
	list = append(list, rm)
	c.marks[pid] = list
}

func (c *Correlator) recentReadsLocked(pid int32, now time.Time, win time.Duration) []readMark {
	list := c.marks[pid]
	if len(list) == 0 {
		return nil
	}

	var valid []readMark
	var recent []readMark
	for _, m := range list {
		if now.Sub(m.at) <= win && !m.at.After(now) {
			valid = append(valid, m)
			recent = append(recent, m)
		} else if now.Sub(m.at) <= 10*time.Minute {
			// keep marks up to 10 minutes to prevent unbounded growth
			valid = append(valid, m)
		}
	}
	c.marks[pid] = valid
	return recent
}

func (c *Correlator) isVendorHost(agentName, host string) bool {
	if host == "" {
		return false
	}
	allowedList, ok := c.cfg.VendorAllowlist[agentName]
	if !ok {
		return false
	}
	hostLower := strings.ToLower(host)
	for _, allowed := range allowedList {
		allowedLower := strings.ToLower(allowed)
		if hostLower == allowedLower || strings.HasSuffix(hostLower, "."+allowedLower) {
			return true
		}
	}
	return false
}

func hashFlagID(rule string, pid int32, ts time.Time) string {
	raw := fmt.Sprintf("%s:%d:%d", rule, pid, ts.UnixNano())
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:8])
}
