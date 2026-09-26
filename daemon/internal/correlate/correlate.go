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
	rule     string
	pid      int32  // the process that opened the file
	exe      string // its executable, when the event carried one
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

// UninspectedWindow is the rolling window the headline count answers over —
// "how many distinct endpoints bypassed inspection RECENTLY", not "since the
// daemon last restarted". A lifetime count inflates monotonically and stops
// meaning anything (operators watched it sit near the thousands for weeks).
const UninspectedWindow = 24 * time.Hour

// uninspectedRetention bounds how long a silent pair is kept for the
// drill-down — long enough to explain a past spike, short enough that the
// set cannot accumulate dead weight forever.
const uninspectedRetention = 7 * 24 * time.Hour

// uninspectedEntry tracks one agent|host pair seen bypassing the proxy.
type uninspectedEntry struct {
	count     int
	lastSeen  time.Time
	firstSeen time.Time
	// sessionID is the most recent session that reached this host — the
	// "which run dialed it" context the operator needs before allowing.
	sessionID string
}

type Correlator struct {
	mu          sync.Mutex
	tagger      *agents.Tagger
	classifier  sensitive.Classifier
	cfg         config.Config
	marks       map[int32][]readMark
	conns       map[int32][]connMark
	uninspected map[string]*uninspectedEntry // distinct "agent|host" egress not seen via the proxy
	// lastFire[rule|pid|subject] — repeat suppression: identical accesses
	// within a rule's window collapse to one flag. An agent touching the
	// same keychain file or leaking to the same host every few minutes is
	// ONE pattern, not a new incident per fire.
	lastFire map[string]time.Time
	// allowlistOverrides supplies user-approved hosts (console suggestions) on
	// top of the config allowlist. Nil until wired.
	allowlistOverrides func(agent string) []string
	// isMuted answers whether a (rule, host) pair has been dispositioned away
	// by the operator for agent. Nil until wired.
	isMuted    func(rule, host, agent string) bool
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
	Agent     string    `json:"agent"`
	Host      string    `json:"host"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
	// SessionID is the most recent session that reached this host.
	SessionID string `json:"session_id,omitempty"`
	// Infra names the CDN/cloud org when the endpoint is known infrastructure
	// (InfraOrg) — empty for genuinely unknown destinations. UIs escalate
	// only the unknown kind; infra rows collapse into a coverage note.
	Infra string `json:"infra,omitempty"`
	// Identity is IdentifyCached(host): the owning org (vendor API, cloud)
	// and cached reverse name. Never a network lookup.
	Identity EndpointIdentity `json:"identity"`
}

// UninspectedEgressSummary lists the observed blind-spot endpoints, most
// frequent first — the input for the console's allowlist suggestions.
func (c *Correlator) UninspectedEgressSummary() []UninspectedSummary {
	return c.UninspectedEgressSummarySince(time.Time{})
}

// UninspectedEgressSummarySince lists blind-spot endpoints last seen at or
// after since (zero time = no window), most frequent first. Powers the
// console's drill-down behind the posture warning.
func (c *Correlator) UninspectedEgressSummarySince(since time.Time) []UninspectedSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneUninspectedLocked(time.Now())
	out := make([]UninspectedSummary, 0, len(c.uninspected))
	for key, e := range c.uninspected {
		if !since.IsZero() && e.lastSeen.Before(since) {
			continue
		}
		agent, host, _ := strings.Cut(key, "|")
		out = append(out, UninspectedSummary{Agent: agent, Host: host, Count: e.count,
			FirstSeen: e.firstSeen, LastSeen: e.lastSeen, SessionID: e.sessionID, Infra: InfraOrg(host),
			Identity: IdentifyCached(host)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// pruneUninspectedLocked drops pairs silent for longer than the retention —
// the set is a blind-spot indicator, not an audit trail. Lock held by caller.
func (c *Correlator) pruneUninspectedLocked(now time.Time) {
	cutoff := now.Add(-uninspectedRetention)
	for k, e := range c.uninspected {
		if e.lastSeen.Before(cutoff) {
			delete(c.uninspected, k)
		}
	}
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

// SetMuteChecker wires operator dispositions: (rule, host) pairs muted for
// the flag's agent are counted, not flagged.
func (c *Correlator) SetMuteChecker(fn func(rule, host, agent string) bool) {
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
	c.pruneUninspectedLocked(time.Now())
	return len(c.uninspected)
}

// UninspectedEgressCountWindow counts only pairs seen within d — the rolling
// headline number the UIs show, so the metric answers "what is bypassing
// inspection NOW" instead of growing monotonically for the daemon's lifetime.
// Known CDN/cloud infrastructure (InfraOrg) is reported separately via
// UninspectedInfraCountWindow and never joins the headline: 130 Cloudflare
// IPs is one routing note, not 130 findings.
func (c *Correlator) UninspectedEgressCountWindow(d time.Duration) int {
	unknown, _ := c.uninspectedCountSplit(d)
	return unknown
}

// UninspectedInfraCountWindow counts in-window pairs classified as known
// CDN/cloud infrastructure — the dimmed "routing coverage" figure.
func (c *Correlator) UninspectedInfraCountWindow(d time.Duration) int {
	_, infra := c.uninspectedCountSplit(d)
	return infra
}

func (c *Correlator) uninspectedCountSplit(d time.Duration) (unknown, infra int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneUninspectedLocked(time.Now())
	cutoff := time.Now().Add(-d)
	for key, e := range c.uninspected {
		if !e.lastSeen.After(cutoff) {
			continue
		}
		_, host, _ := strings.Cut(key, "|")
		if InfraOrg(host) != "" {
			infra++
		} else {
			unknown++
		}
	}
	return
}

func isLocalhost(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "localhost", "":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

// keychainRepeatWindow: repeats of the same (pid, keychain path) access
// within this window are the same pattern — one flag, not a flood.
const keychainRepeatWindow = 15 * time.Minute

// Repeat windows per rule: identical fires within the window are ONE
// pattern. Tuned per rule — TCC writes are rare (long window), proxy leaks
// recur while an agent runs (short window).
var repeatWindows = map[string]time.Duration{
	"keychain-access":        15 * time.Minute,
	"keychain-security-cli":  15 * time.Minute,
	"tcc-tamper":             60 * time.Minute,
	"proxy-secret-leak":      5 * time.Minute,
	"proxy-prompt-injection": 15 * time.Minute,
	"secret-in-transcript":   15 * time.Minute,
}

// shouldFlag reports whether this (rule, pid, subject) fire is new within
// the rule's repeat window. Returns false (and records the fire) when a
// repeat within the window was already flagged — the caller drops it.
// Callers hold c.mu.
func (c *Correlator) shouldFlag(rule string, pid int32, subject string, ts time.Time, window time.Duration) bool {
	if c.lastFire == nil {
		c.lastFire = map[string]time.Time{}
	}
	key := fmt.Sprintf("%s|%d|%s", rule, pid, subject)
	if last, ok := c.lastFire[key]; ok && ts.Sub(last) < window {
		return false
	}
	c.lastFire[key] = ts
	// Bound the map: prune entries past 4x the largest window.
	if len(c.lastFire) > 1024 {
		for k, t := range c.lastFire {
			if ts.Sub(t) > 4*time.Hour {
				delete(c.lastFire, k)
			}
		}
	}
	return true
}

func (c *Correlator) Observe(e event.Event) []model.Flag {
	c.mu.Lock()
	defer c.mu.Unlock()
	flags := c.observeLocked(e)
	c.stampProcessLocked(flags)
	return flags
}

// stampProcessLocked snapshots each raising process into its flag, so the
// finding still names the process after it exits.
func (c *Correlator) stampProcessLocked(flags []model.Flag) {
	for i := range flags {
		if flags[i].Process != nil || flags[i].PID <= 0 {
			continue
		}
		if p, ok := c.tagger.Snapshot(flags[i].PID); ok {
			flags[i].Process = &p
		}
	}
}

func (c *Correlator) observeLocked(e event.Event) []model.Flag {
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
		if c.isMuted != nil && (c.isMuted(ruleName, e.RemoteHost, agentName) ||
			(isLocalhost(e.RemoteHost) && c.isMuted(ruleName, "localhost", agentName))) {
			c.mutedCount++
			return nil
		}
		if !c.shouldFlag(ruleName, e.PID, e.RemoteHost, e.TS, repeatWindows[ruleName]) {
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
				Evidence: []model.EvidenceItem{{
					Kind:  "violation",
					Label: e.Detail,
					Sub:   "payload inspection",
					Text:  fmt.Sprintf("Local proxy detected security violation '%s' while connecting to %s:%d", e.Detail, e.RemoteHost, e.RemotePort),
				}, {
					Kind:  "connect",
					Label: fmt.Sprintf("%s:%d", e.RemoteHost, e.RemotePort),
					Sub:   "destination",
				}},
			},
		}
	}

	// Transcript hits carry no pid: the harness named in Detail is the agent.
	if e.Kind == event.KindTranscriptHit {
		return c.secretInTranscriptLocked(e)
	}

	info, isAgent := c.tagger.Tag(e.PID)
	if !isAgent {
		return c.untaggedKeychainLocked(e)
	}

	rootPID := e.PID
	if len(info.Chain) > 0 {
		rootPID = info.Chain[len(info.Chain)-1]
	}

	var flags []model.Flag

	switch e.Kind {
	case event.KindFileOpen, event.KindFileWrite, event.KindPluginAction:
		if m, ok := c.classifier.Match(e.Path); ok {
			cat := m.Category
			if cat == sensitive.CatKeychain {
				flags = append(flags, c.keychainAccessLocked(e, info.Name)...)
			}
			if seedsReadThenConnect(m.Category, e.Kind, e.ExePath) {
				c.rememberReadLocked(rootPID, e.PID, readMark{at: e.TS, path: e.Path, cat: cat, rule: m.Rule, pid: e.PID, exe: e.ExePath})
				// Check if there's already an unconsumed recent foreign connection for this agent
				recentConns := c.recentConnsLocked(rootPID, e.PID, e.TS, window)
				// Operator disposition applies only when EVERY connection the
				// flag would cite is muted — a fresh unmuted host must still flag.
				mutedAll := c.isMuted != nil && len(recentConns) > 0
				if mutedAll {
					for _, cm := range recentConns {
						h := cm.host
						if isLocalhost(h) {
							h = "localhost" // canonical alias: one mute covers the family
						}
						if !c.isMuted("sensitive-read-then-connect", h, info.Name) {
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
					evidence := []model.EvidenceItem{{
						Kind:  "read",
						Label: e.Path,
						Sub:   "sensitive read",
						Rule:  m.Rule,
						TS:    e.TS.Format(time.RFC3339),
						Text:  fmt.Sprintf("%s (pid %d) read %s at %s", info.Name, e.PID, e.Path, e.TS.Format(time.RFC3339)),
						PID:   e.PID,
						Exe:   e.ExePath,
					}}
					for _, cm := range recentConns {
						evidence = append(evidence, model.EvidenceItem{
							Kind:  "connect",
							Label: fmt.Sprintf("%s:%d", cm.host, cm.port),
							Sub:   "egress",
							TS:    cm.at.Format(time.RFC3339),
							Text:  fmt.Sprintf("then connected to %s:%d at %s", cm.host, cm.port, cm.at.Format(time.RFC3339)),
						})
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
			if c.isMuted != nil && c.isMuted("keychain-security-cli", "*", info.Name) {
				c.mutedCount++
				return nil
			}
			if !c.shouldFlag("keychain-security-cli", e.PID, "", e.TS, repeatWindows["keychain-security-cli"]) {
				return nil
			}
			flagID := hashFlagID("keychain-security-cli", e.PID, e.TS)
			flags = append(flags, model.Flag{
				ID:        flagID,
				Rule:      "keychain-security-cli",
				Severity:  3,
				TS:        e.TS,
				PID:       e.PID,
				Agent:     info.Name,
				SessionID: e.SessionID,
				Evidence: []model.EvidenceItem{{
					Kind:  "exec",
					Label: e.ExePath,
					Sub:   "keychain CLI",
					TS:    e.TS.Format(time.RFC3339),
					Text:  fmt.Sprintf("%s (pid %d) executed %s at %s", info.Name, e.PID, e.ExePath, e.TS.Format(time.RFC3339)),
				}},
			})
		}

	case event.KindTCCModify:
		// Rule 4: TCC tamper. An agent touching the Transparency, Consent, and
		// Control database (even reads of the service list) is probing or
		// escalating its permissions — screen recording, accessibility, and
		// automation grants are the classic over-reach targets. Severity 3:
		// there is no benign reason for an agent process to be here.
		if !c.shouldFlag("tcc-tamper", e.PID, e.Detail, e.TS, repeatWindows["tcc-tamper"]) {
			return nil
		}
		flags = append(flags, model.Flag{
			ID:        hashFlagID("tcc-tamper", e.PID, e.TS),
			Rule:      "tcc-tamper",
			Severity:  3,
			TS:        e.TS,
			PID:       e.PID,
			Agent:     info.Name,
			SessionID: e.SessionID,
			Evidence: []model.EvidenceItem{{
				Kind:  "tcc",
				Label: e.Detail,
				Sub:   "privacy tamper",
				TS:    e.TS.Format(time.RFC3339),
				Text:  fmt.Sprintf("%s (pid %d) modified TCC service '%s' at %s", info.Name, e.PID, e.Detail, e.TS.Format(time.RFC3339)),
			}},
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
				if e.SessionID != "" {
					e2.sessionID = e.SessionID
				}
				// Advisor pre-assessment is for endpoints a human must judge —
				// never spend model calls on carriers or on the agents' own
				// vendors (Anthropic, OpenAI, GitHub, registries). Cloud and
				// telemetry hosts can front anyone, so they are still assessed.
				if e2.count == 3 && c.onUninspected != nil &&
					IdentifyCached(e.RemoteHost).Class != "vendor" && InfraOrg(e.RemoteHost) == "" {
					c.onUninspected(info.Name, e.RemoteHost)
				}
			} else if len(c.uninspected) < maxUninspectedTracked {
				c.uninspected[key] = &uninspectedEntry{count: 1, firstSeen: e.TS, lastSeen: e.TS, sessionID: e.SessionID}
			}
		}

		c.rememberConnLocked(rootPID, e.PID, connMark{at: e.TS, host: e.RemoteHost, port: e.RemotePort})

		recent := c.recentReadsLocked(rootPID, e.PID, e.TS, window)
		if len(recent) == 0 {
			return nil
		}

		// Operator disposition: a muted (rule, host) pair is counted, not
		// flagged — the read-then-connect evidence would only repeat it.
		if c.isMuted != nil && c.isMuted("sensitive-read-then-connect", e.RemoteHost, info.Name) {
			c.mutedCount++
			c.markReadConsumedLocked(rootPID, e.PID)
			c.markConnConsumedLocked(rootPID, e.PID)
			return nil
		}

		// Rule 1: sensitive-read-then-connect
		flagID := hashFlagID("sensitive-read-then-connect", rootPID, recent[0].at)
		var evidence []model.EvidenceItem
		for _, m := range recent {
			evidence = append(evidence, model.EvidenceItem{
				Kind:  "read",
				Label: m.path,
				Sub:   "sensitive read",
				Rule:  m.rule,
				TS:    m.at.Format(time.RFC3339),
				Text:  fmt.Sprintf("%s (pid %d) read %s at %s", info.Name, m.pid, m.path, m.at.Format(time.RFC3339)),
				PID:   m.pid,
				Exe:   m.exe,
			})
		}
		evidence = append(evidence, model.EvidenceItem{
			Kind:  "connect",
			Label: fmt.Sprintf("%s:%d", e.RemoteHost, e.RemotePort),
			Sub:   "egress",
			TS:    e.TS.Format(time.RFC3339),
			Text:  fmt.Sprintf("then connected to %s:%d at %s", e.RemoteHost, e.RemotePort, e.TS.Format(time.RFC3339)),
		})

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

// secretInTranscriptLocked applies the secret-in-transcript rule to one
// transcript hit (Detail "<harness>:<layer>:<rule id>"). A registered known
// secret (fingerprint layer) is severity 3; a typed pattern is severity 2.
// Callers hold c.mu.
func (c *Correlator) secretInTranscriptLocked(e event.Event) []model.Flag {
	const rule = "secret-in-transcript"
	parts := strings.SplitN(e.Detail, ":", 3)
	if len(parts) != 3 || parts[2] == "" {
		return nil
	}
	harness, layer, ruleID := parts[0], parts[1], parts[2]
	if c.isMuted != nil && c.isMuted(rule, "*", harness) {
		c.mutedCount++
		return nil
	}
	if !c.shouldFlag(rule, 0, e.Path+"|"+ruleID, e.TS, repeatWindows[rule]) {
		return nil
	}
	severity := 2
	if layer == "fingerprint" {
		severity = 3
	}
	return []model.Flag{{
		ID:        hashFlagID(rule+"|"+e.Path+"|"+ruleID, 0, e.TS),
		Rule:      rule,
		Severity:  severity,
		TS:        e.TS,
		Agent:     harness,
		SessionID: e.SessionID,
		Evidence: []model.EvidenceItem{{
			Kind:   "transcript",
			Label:  e.Path,
			Sub:    layer + " match",
			Rule:   ruleID,
			TS:     e.TS.Format(time.RFC3339),
			Text:   fmt.Sprintf("%s transcript %s matched %s rule %s at %s", harness, e.Path, layer, ruleID, e.TS.Format(time.RFC3339)),
			Offset: e.Offset,
		}},
	}}
}

// keychainAccessLocked applies the keychain-access rule to one login-keychain
// file access attributed to agent. Callers hold c.mu.
func (c *Correlator) keychainAccessLocked(e event.Event, agent string) []model.Flag {
	// Operator disposition: a rule-level mute (host "*") silences the
	// class — counted so the quiet is deliberate, never hidden.
	if c.isMuted != nil && c.isMuted("keychain-access", "*", agent) {
		c.mutedCount++
		return nil
	}
	// Repeat suppression: an agent touching the same keychain file
	// every few minutes is ONE access pattern, not a new incident
	// per fire. Collapse repeats within the window. Without this,
	// one routine access pattern floods the critical list with
	// dozens of identical rows — the operator's "ignore" looked
	// broken because the NEXT fire was a new flag id.
	if !c.shouldFlag("keychain-access", e.PID, e.Path, e.TS, keychainRepeatWindow) {
		return nil
	}
	return []model.Flag{{
		ID:        hashFlagID("keychain-access", e.PID, e.TS),
		Rule:      "keychain-access",
		Severity:  1,
		TS:        e.TS,
		PID:       e.PID,
		Agent:     agent,
		SessionID: e.SessionID,
		Evidence: []model.EvidenceItem{{
			Kind:  "keychain",
			Label: e.Path,
			Sub:   "keychain access",
			TS:    e.TS.Format(time.RFC3339),
			Text:  fmt.Sprintf("%s (pid %d) accessed keychain file %s at %s", agent, e.PID, e.Path, e.TS.Format(time.RFC3339)),
		}},
	}}
}

// systemExePrefixes are the OS-owned install locations. Login-keychain opens
// by executables under them are platform behavior, not an untagged process
// reaching for credentials.
var systemExePrefixes = []string{"/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/"}

func isSystemExe(exe string) bool {
	for _, p := range systemExePrefixes {
		if strings.HasPrefix(exe, p) {
			return true
		}
	}
	return false
}

// untaggedKeychainLocked applies the keychain-access rule to a process the
// tagger has not tagged. Only login-keychain file opens and writes by an
// executable outside the system prefixes qualify. An exe the agent match
// strings name joins that agent's flags; any other is "untagged:<label>".
// Callers hold c.mu.
func (c *Correlator) untaggedKeychainLocked(e event.Event) []model.Flag {
	if e.Kind != event.KindFileOpen && e.Kind != event.KindFileWrite {
		return nil
	}
	if e.ExePath == "" || isSystemExe(e.ExePath) {
		return nil
	}
	if m, ok := c.classifier.Match(e.Path); !ok || m.Category != sensitive.CatKeychain {
		return nil
	}
	agent := untaggedLabel(e.ExePath)
	if name, ok := c.tagger.MatchExe(e.ExePath); ok {
		agent = name
	}
	return c.keychainAccessLocked(e, agent)
}

// genericExeDirs name directories that say nothing about who ships the
// binary under them.
var genericExeDirs = map[string]bool{"versions": true, "version": true, "bin": true, "libexec": true, "current": true}

// untaggedLabel is "untagged:<exe basename>"; a version-number basename
// (".../claude/versions/2.1.280") is prefixed with the nearest parent that is
// neither generic nor a version: "untagged:claude 2.1.280".
func untaggedLabel(exe string) string {
	base := filepath.Base(exe)
	if !isVersionString(base) {
		return "untagged:" + base
	}
	for dir := filepath.Dir(exe); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		name := filepath.Base(dir)
		if genericExeDirs[strings.ToLower(name)] || isVersionString(name) {
			continue
		}
		return "untagged:" + name + " " + base
	}
	return "untagged:" + base
}

// isVersionString: digits and dots only, at least one digit.
func isVersionString(s string) bool {
	digit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r != '.':
			return false
		}
	}
	return digit
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
	for _, allowed := range c.cfg.VendorAllowlist[agentName] {
		if HostMatches(host, allowed) {
			return true
		}
	}
	// User-approved hosts (console allowlist suggestions) count as vendor
	// traffic for this agent.
	if c.allowlistOverrides != nil {
		for _, allowed := range c.allowlistOverrides(agentName) {
			if HostMatches(host, allowed) {
				return true
			}
		}
	}
	return false
}

// HostMatches: host equals allowed or is a subdomain of it (dot boundary),
// case-insensitive. The one match rule for vendor and user-approved hosts.
func HostMatches(host, allowed string) bool {
	if host == "" || allowed == "" {
		return false
	}
	h, a := strings.ToLower(host), strings.ToLower(allowed)
	return h == a || strings.HasSuffix(h, "."+a)
}

func hashFlagID(rule string, pid int32, ts time.Time) string {
	raw := fmt.Sprintf("%s:%d:%d", rule, pid, ts.UnixNano())
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:8])
}
