package correlate

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
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

// maxUninspectedTracked bounds the uninspected-egress set. Without a cap it
// gains one entry per distinct agent|host pair for the life of the daemon. The
// metric is a blind-spot indicator, not an audit trail: once saturated it stays
// saturated (and signals "lots of distinct egress") rather than growing forever.
const maxUninspectedTracked = 4096

// uninspectedEntry tracks one agent|host pair seen bypassing the proxy.
type uninspectedEntry struct {
	count    int
	lastSeen time.Time
}

type Correlator struct {
	mu          sync.Mutex
	tagger      *agents.Tagger
	classifier  sensitive.Classifier
	cfg         config.Config
	marks       map[int32][]readMark
	conns       map[int32][]connMark
	uninspected map[string]*uninspectedEntry // distinct "agent|host" egress not seen via the proxy
	// allowlistOverrides supplies user-approved hosts (console suggestions) on
	// top of the config allowlist. Nil until wired.
	allowlistOverrides func(agent string) []string
	// isMuted answers whether a (rule, host) pair has been dispositioned away
	// by the operator. Nil until wired.
	isMuted    func(rule, host string) bool
	mutedCount int
	// onUninspected fires once when an endpoint first crosses the suggestion
	// threshold — the advisor's cue to pre-assess the host before the
	// operator ever sees the suggestion. Nil until wired.
	onUninspected func(agent, host string)
}

func New(tagger *agents.Tagger, classifier sensitive.Classifier, cfg config.Config) *Correlator {
	return &Correlator{
		tagger:      tagger,
		classifier:  classifier,
		cfg:         cfg,
		marks:       make(map[int32][]readMark),
		conns:       make(map[int32][]connMark),
		uninspected: make(map[string]*uninspectedEntry),
	}
}

// UninspectedSummary is one agent+host pair observed bypassing inspection.
type UninspectedSummary struct {
	Agent    string    `json:"agent"`
	Host     string    `json:"host"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// UninspectedEgressSummary lists the observed blind-spot endpoints, most
// frequent first — the input for the console's allowlist suggestions.
func (c *Correlator) UninspectedEgressSummary() []UninspectedSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]UninspectedSummary, 0, len(c.uninspected))
	for key, e := range c.uninspected {
		agent, host, _ := strings.Cut(key, "|")
		out = append(out, UninspectedSummary{Agent: agent, Host: host, Count: e.count, LastSeen: e.lastSeen})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// SetAllowlistOverrides wires the user-approved host list (persisted by the
// AllowlistStore) into vendor-host recognition.
func (c *Correlator) SetAllowlistOverrides(fn func(agent string) []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowlistOverrides = fn
}

// NoteAllowlistAdded drops the agent|host pair from the blind-spot set once
// the user approves it — the metric should reflect what is STILL unseen.
func (c *Correlator) NoteAllowlistAdded(agent, host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.uninspected, agent+"|"+strings.ToLower(host))
}

// SetMuteChecker wires operator dispositions: muted (rule, host) pairs are
// counted, not flagged.
func (c *Correlator) SetMuteChecker(fn func(rule, host string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isMuted = fn
}

// SetOnUninspected wires the suggestion-threshold hook (advisor host
// pre-assessment). Fires with the correlator lock HELD — the callback must
// be non-blocking (enqueue, never call back into the correlator).
func (c *Correlator) SetOnUninspected(fn func(agent, host string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onUninspected = fn
}

// MutedCount reports how many flags were suppressed by dispositions — proof
// the operator's "stop telling me" is working, not a hidden silence.
func (c *Correlator) MutedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mutedCount
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
		// Operator disposition: muted (rule, host) pairs are counted, not flagged.
		if c.isMuted != nil && c.isMuted(ruleName, e.RemoteHost) {
			c.mutedCount++
			return nil
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
				// Operator disposition applies only when EVERY connection the
				// flag would cite is muted — a fresh unmuted host must still flag.
				mutedAll := c.isMuted != nil && len(recentConns) > 0
				if mutedAll {
					for _, cm := range recentConns {
						if !c.isMuted("sensitive-read-then-connect", cm.host) {
							mutedAll = false
							break
						}
					}
				}
				if mutedAll {
					c.mutedCount++
					c.markReadConsumedLocked(rootPID, e.PID)
					c.markConnConsumedLocked(rootPID, e.PID)
				} else if len(recentConns) > 0 {
					flagID := hashFlagID("sensitive-read-then-connect", rootPID, recentConns[0].at)
					evidence := []string{
						fmt.Sprintf("%s (pid %d) read %s at %s", info.Name, e.PID, e.Path, e.TS.Format(time.RFC3339)),
					}
					for _, cm := range recentConns {
						evidence = append(evidence, fmt.Sprintf("then connected to %s:%d at %s", cm.host, cm.port, cm.at.Format(time.RFC3339)))
					}
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
			}
		}

	case event.KindExec:
		// Rule 3: keychain CLI. Any execution of macOS security(1) by a tagged
		// agent is flagged regardless of subcommand — reads (dump-keychain,
		// find-generic-password) and writes (add/modify/delete) are both
		// exfiltration and tampering vectors, and argv beyond argv[0] arrives
		// untrusted from eslogger.
		base := strings.ToLower(filepath.Base(e.ExePath))
		if base == "security" {
			flagID := hashFlagID("keychain-security-cli", e.PID, e.TS)
			flags = append(flags, model.Flag{
				ID:        flagID,
				Rule:      "keychain-security-cli",
				Severity:  3,
				TS:        e.TS,
				PID:       e.PID,
				Agent:     info.Name,
				SessionID: e.SessionID,
				Evidence: []string{
					fmt.Sprintf("%s (pid %d) executed %s at %s", info.Name, e.PID, e.ExePath, e.TS.Format(time.RFC3339)),
				},
			})
		}

	case event.KindTCCModify:
		// Rule 4: TCC tamper. An agent touching the Transparency, Consent, and
		// Control database (even reads of the service list) is probing or
		// escalating its permissions — screen recording, accessibility, and
		// automation grants are the classic over-reach targets. Severity 3:
		// there is no benign reason for an agent process to be here.
		flags = append(flags, model.Flag{
			ID:        hashFlagID("tcc-tamper", e.PID, e.TS),
			Rule:      "tcc-tamper",
			Severity:  3,
			TS:        e.TS,
			PID:       e.PID,
			Agent:     info.Name,
			SessionID: e.SessionID,
			Evidence: []string{
				fmt.Sprintf("%s (pid %d) modified TCC service '%s' at %s", info.Name, e.PID, e.Detail, e.TS.Format(time.RFC3339)),
			},
		})

	case event.KindConnOpen:
		if c.isVendorHost(info.Name, e.RemoteHost) {
			return nil
		}

		// A tagged agent connecting to a non-localhost host went out without
		// transiting the proxy (routed traffic targets 127.0.0.1). Record it as a
		// coverage metric; do not flag (that would alarm on every github/npm call).
		if !isLocalhost(e.RemoteHost) {
			key := info.Name + "|" + e.RemoteHost
			if e2, known := c.uninspected[key]; known {
				e2.count++
				e2.lastSeen = e.TS
				if e2.count == 3 && c.onUninspected != nil {
					c.onUninspected(info.Name, e.RemoteHost)
				}
			} else if len(c.uninspected) < maxUninspectedTracked {
				c.uninspected[key] = &uninspectedEntry{count: 1, lastSeen: e.TS}
			}
		}

		c.rememberConnLocked(rootPID, e.PID, connMark{at: e.TS, host: e.RemoteHost, port: e.RemotePort})

		recent := c.recentReadsLocked(rootPID, e.PID, e.TS, window)
		if len(recent) == 0 {
			return nil
		}

		// Operator disposition: a muted (rule, host) pair is counted, not
		// flagged — the read-then-connect evidence would only repeat it.
		if c.isMuted != nil && c.isMuted("sensitive-read-then-connect", e.RemoteHost) {
			c.mutedCount++
			c.markReadConsumedLocked(rootPID, e.PID)
			c.markConnConsumedLocked(rootPID, e.PID)
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
	hostLower := strings.ToLower(host)
	matches := func(allowed string) bool {
		allowedLower := strings.ToLower(allowed)
		return hostLower == allowedLower || strings.HasSuffix(hostLower, "."+allowedLower)
	}
	for _, allowed := range c.cfg.VendorAllowlist[agentName] {
		if matches(allowed) {
			return true
		}
	}
	// User-approved hosts (console allowlist suggestions) count as vendor
	// traffic for this agent.
	if c.allowlistOverrides != nil {
		for _, allowed := range c.allowlistOverrides(agentName) {
			if matches(allowed) {
				return true
			}
		}
	}
	return false
}

func hashFlagID(rule string, pid int32, ts time.Time) string {
	raw := fmt.Sprintf("%s:%d:%d", rule, pid, ts.UnixNano())
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:8])
}
