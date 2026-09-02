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
	at       time.Time
	path     string
	cat      sensitive.Category
	consumed bool
}

type connMark struct {
	at       time.Time
	host     string
	port     int
	consumed bool
}

const window = 60 * time.Second

type Correlator struct {
	mu          sync.Mutex
	tagger      *agents.Tagger
	classifier  sensitive.Classifier
	cfg         config.Config
	marks       map[int32][]readMark
	conns       map[int32][]connMark
	uninspected map[string]struct{} // distinct "agent|host" egress not seen via the proxy
}

func New(tagger *agents.Tagger, classifier sensitive.Classifier, cfg config.Config) *Correlator {
	return &Correlator{
		tagger:      tagger,
		classifier:  classifier,
		cfg:         cfg,
		marks:       make(map[int32][]readMark),
		conns:       make(map[int32][]connMark),
		uninspected: make(map[string]struct{}),
	}
}

// UninspectedEgressCount reports the number of distinct agent+host egress
// endpoints observed connecting directly (not via the local inspection proxy,
// which agents reach on 127.0.0.1). It is a coverage/blind-spot signal, not an
// alarm, so it is surfaced as a metric rather than a per-connection flag.
func (c *Correlator) UninspectedEgressCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.uninspected)
}

func isLocalhost(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "localhost", "":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

func (c *Correlator) Observe(e event.Event) []model.Flag {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictStaleLocked(e.TS)

	if e.Kind == event.KindProxyHit {
		ruleName := "proxy-payload-inspection"
		if strings.HasPrefix(e.Detail, "proxy-secret-leak") {
			ruleName = "proxy-secret-leak"
		} else if strings.HasPrefix(e.Detail, "proxy-prompt-injection") {
			ruleName = "proxy-prompt-injection"
		}
		flagID := hashFlagID(ruleName, e.PID, e.TS)
		agentName := "proxy"
		if info, isAgent := c.tagger.Tag(e.PID); isAgent {
			agentName = info.Name
		}
		return []model.Flag{
			{
				ID:        flagID,
				Rule:      ruleName,
				Severity:  3,
				TS:        e.TS,
				PID:       e.PID,
				Agent:     agentName,
				SessionID: e.SessionID,
				Evidence: []string{
					fmt.Sprintf("Local proxy detected security violation '%s' while connecting to %s:%d", e.Detail, e.RemoteHost, e.RemotePort),
				},
			},
		}
	}

	info, isAgent := c.tagger.Tag(e.PID)
	if !isAgent {
		return nil
	}

	rootPID := e.PID
	if len(info.Chain) > 0 {
		rootPID = info.Chain[len(info.Chain)-1]
	}

	var flags []model.Flag

	switch e.Kind {
	case event.KindFileOpen, event.KindFileWrite, event.KindPluginAction:
		if cat, ok := c.classifier.Classify(e.Path); ok {
			c.rememberReadLocked(rootPID, e.PID, readMark{at: e.TS, path: e.Path, cat: cat})
			if cat == sensitive.CatKeychain {
				// Rule 2: Keychain access flags immediately
				flagID := hashFlagID("keychain-access", e.PID, e.TS)
				evidence := []string{
					fmt.Sprintf("%s (pid %d) accessed keychain file %s at %s", info.Name, e.PID, e.Path, e.TS.Format(time.RFC3339)),
				}
				flags = append(flags, model.Flag{
					ID:        flagID,
					Rule:      "keychain-access",
					Severity:  2,
					TS:        e.TS,
					PID:       e.PID,
					Agent:     info.Name,
					SessionID: e.SessionID,
					Evidence:  evidence,
				})
			} else {
				// Check if there's already an unconsumed recent foreign connection for this agent
				recentConns := c.recentConnsLocked(rootPID, e.PID, e.TS, window)
				if len(recentConns) > 0 {
					flagID := hashFlagID("sensitive-read-then-connect", rootPID, recentConns[0].at)
					evidence := []string{
						fmt.Sprintf("%s (pid %d) read %s at %s", info.Name, e.PID, e.Path, e.TS.Format(time.RFC3339)),
					}
					for _, cm := range recentConns {
						evidence = append(evidence, fmt.Sprintf("then connected to %s:%d at %s", cm.host, cm.port, cm.at.Format(time.RFC3339)))
					}
					flags = append(flags, model.Flag{
						ID:       flagID,
						Rule:     "sensitive-read-then-connect",
						Severity: 3,
						TS:       e.TS,
						PID:      e.PID,
						Agent:    info.Name,
						Evidence: evidence,
					})
					c.markReadConsumedLocked(rootPID, e.PID)
					c.markConnConsumedLocked(rootPID, e.PID)
				}
			}
		}

	case event.KindConnOpen:
		if c.isVendorHost(info.Name, e.RemoteHost) {
			return nil
		}

		// A tagged agent connecting to a non-localhost host went out without
		// transiting the proxy (routed traffic targets 127.0.0.1). Record it as a
		// coverage metric; do not flag (that would alarm on every github/npm call).
		if !isLocalhost(e.RemoteHost) {
			c.uninspected[info.Name+"|"+e.RemoteHost] = struct{}{}
		}

		c.rememberConnLocked(rootPID, e.PID, connMark{at: e.TS, host: e.RemoteHost, port: e.RemotePort})

		recent := c.recentReadsLocked(rootPID, e.PID, e.TS, window)
		if len(recent) == 0 {
			return nil
		}

		// Rule 1: sensitive-read-then-connect
		flagID := hashFlagID("sensitive-read-then-connect", rootPID, recent[0].at)
		var evidence []string
		for _, m := range recent {
			evidence = append(evidence, fmt.Sprintf("%s (pid %d) read %s at %s", info.Name, e.PID, m.path, m.at.Format(time.RFC3339)))
		}
		evidence = append(evidence, fmt.Sprintf("then connected to %s:%d at %s", e.RemoteHost, e.RemotePort, e.TS.Format(time.RFC3339)))

		flags = append(flags, model.Flag{
			ID:        flagID,
			Rule:      "sensitive-read-then-connect",
			Severity:  3,
			TS:        e.TS,
			PID:       e.PID,
			Agent:     info.Name,
			SessionID: e.SessionID,
			Evidence:  evidence,
		})
		c.markReadConsumedLocked(rootPID, e.PID)
		c.markConnConsumedLocked(rootPID, e.PID)
	}

	return flags
}

func (c *Correlator) rememberReadLocked(pid int32, directPID int32, rm readMark) {
	for _, p := range []int32{pid, directPID} {
		if p == 0 {
			continue
		}
		list := c.marks[p]
		if len(list) >= 50 {
			list = list[1:]
		}
		list = append(list, rm)
		c.marks[p] = list
	}
}

func (c *Correlator) rememberConnLocked(pid int32, directPID int32, cm connMark) {
	for _, p := range []int32{pid, directPID} {
		if p == 0 {
			continue
		}
		list := c.conns[p]
		if len(list) >= 50 {
			list = list[1:]
		}
		list = append(list, cm)
		c.conns[p] = list
	}
}

func (c *Correlator) markReadConsumedLocked(pid int32, directPID int32) {
	for _, p := range []int32{pid, directPID} {
		if p == 0 {
			continue
		}
		list := c.marks[p]
		for i := range list {
			list[i].consumed = true
		}
		c.marks[p] = list
	}
}

func (c *Correlator) markConnConsumedLocked(pid int32, directPID int32) {
	for _, p := range []int32{pid, directPID} {
		if p == 0 {
			continue
		}
		list := c.conns[p]
		for i := range list {
			list[i].consumed = true
		}
		c.conns[p] = list
	}
}

func (c *Correlator) recentReadsLocked(pid int32, directPID int32, now time.Time, win time.Duration) []readMark {
	list := c.marks[pid]
	if len(list) == 0 && directPID != 0 && directPID != pid {
		list = c.marks[directPID]
	}
	if len(list) == 0 {
		return nil
	}

	var valid []readMark
	var recent []readMark
	for _, m := range list {
		diff := now.Sub(m.at)
		if diff >= -15*time.Second && diff <= win {
			valid = append(valid, m)
			if !m.consumed {
				recent = append(recent, m)
			}
		} else if diff <= 10*time.Minute {
			valid = append(valid, m)
		}
	}
	c.marks[pid] = valid
	if directPID != 0 && directPID != pid {
		c.marks[directPID] = valid
	}
	return recent
}

func (c *Correlator) recentConnsLocked(pid int32, directPID int32, now time.Time, win time.Duration) []connMark {
	list := c.conns[pid]
	if len(list) == 0 && directPID != 0 && directPID != pid {
		list = c.conns[directPID]
	}
	if len(list) == 0 {
		return nil
	}

	var valid []connMark
	var recent []connMark
	for _, cm := range list {
		diff := now.Sub(cm.at)
		if diff >= -15*time.Second && diff <= win {
			valid = append(valid, cm)
			if !cm.consumed {
				recent = append(recent, cm)
			}
		} else if diff <= 10*time.Minute {
			valid = append(valid, cm)
		}
	}
	c.conns[pid] = valid
	if directPID != 0 && directPID != pid {
		c.conns[directPID] = valid
	}
	return recent
}

func (c *Correlator) evictStaleLocked(now time.Time) {
	for pid, list := range c.marks {
		var valid []readMark
		for _, m := range list {
			if now.Sub(m.at) <= 10*time.Minute {
				valid = append(valid, m)
			}
		}
		if len(valid) == 0 {
			delete(c.marks, pid)
		} else {
			c.marks[pid] = valid
		}
	}

	for pid, list := range c.conns {
		var valid []connMark
		for _, cm := range list {
			if now.Sub(cm.at) <= 10*time.Minute {
				valid = append(valid, cm)
			}
		}
		if len(valid) == 0 {
			delete(c.conns, pid)
		} else {
			c.conns[pid] = valid
		}
	}
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
