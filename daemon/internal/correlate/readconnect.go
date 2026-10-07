package correlate

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const readConnectRule = "sensitive-read-then-connect"

// readRepeatWindow: one read-then-connect pattern (agent, reader, secret,
// destination org) raises one flag per window; repeats fold into it.
const readRepeatWindow = 60 * time.Minute

type foldedFlag struct {
	id       string
	at       time.Time
	severity int
}

type flagRepeat struct {
	id string
	at time.Time
}

// SetOnRepeat wires the sink for repeats folded into an open flag. It runs
// after Observe releases the correlator lock.
func (c *Correlator) SetOnRepeat(fn func(flagID string, at time.Time)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onRepeat = fn
}

// CredentialOwnerUses counts connections judged a credential used with its
// owner (recorded, not flagged).
func (c *Correlator) CredentialOwnerUses() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ownerUseCount
}

// credentialOwners returns the orgs that own the credential at path: the
// first credential_owners entry that is path or a directory above it.
func (c *Correlator) credentialOwners(path string) []string {
	for _, o := range c.cfg.CredentialOwners {
		if path == o.Path || strings.HasPrefix(path, o.Path+"/") {
			return o.Orgs
		}
	}
	return nil
}

// ownerUse reports whether cm is the credential in every file read used
// with its owner: for each file, a read of it came from the connection's own
// process tree (or the narrowly matched GitHub helper), and an org that owns
// the file is the destination. Other
// processes reading the same file do not change that. An agent tool read
// never qualifies: it put the file into the model's context.
func (c *Correlator) ownerUse(reads []readMark, cm connMark) bool {
	org := hostid.IdentifyCached(cm.host).Org
	if org == "" || cm.pid == 0 || len(reads) == 0 {
		return false
	}
	explained := map[string]bool{}
	for _, r := range reads {
		if r.kind == event.KindPluginAction {
			return false // A native read of the same path cannot undo model exposure.
		}
		ok := r.kind == event.KindFileOpen && (sameTree(r, cm) || githubCredentialSibling(r, cm)) && slices.Contains(c.credentialOwners(r.path), org)
		explained[r.path] = explained[r.path] || ok
	}
	for _, ok := range explained {
		if !ok {
			return false
		}
	}
	return true
}

// githubCredentialSibling covers gh's credential helper beside a Git client
// under the same immediate parent. A broad agent-family or cloud-provider
// match is insufficient. Unknown executables retain the review finding.
func githubCredentialSibling(r readMark, cm connMark) bool {
	if r.kind != event.KindFileOpen || filepath.Base(r.exe) != "gh" || !strings.HasSuffix(r.path, "/.config/gh/hosts.yml") ||
		cm.port != 443 || len(r.chain) < 3 || len(cm.chain) < 3 || r.pid == cm.pid ||
		r.chain[0] != r.pid || cm.chain[0] != cm.pid || r.chain[1] <= 1 || r.chain[1] != cm.chain[1] {
		return false
	}
	gap := cm.at.Sub(r.at)
	if gap < -5*time.Second || gap > 5*time.Second {
		return false
	}
	switch filepath.Base(cm.exe) {
	case "git", "git-remote-https", "gh":
	default:
		return false
	}
	host := DestLabel(cm.host)
	if host == "github.com" || host == "api.github.com" || (strings.HasPrefix(host, "lb-") && strings.HasSuffix(host, ".github.com")) {
		return true
	}
	// Restrict bare addresses to the existing GitHub API/Git ranges, excluding
	// Pages/user-content ranges and shared CDN infrastructure.
	ip, err := netip.ParseAddr(host)
	return err == nil && (netip.MustParsePrefix("140.82.112.0/20").Contains(ip) || netip.MustParsePrefix("192.30.252.0/22").Contains(ip))
}

// sameTree reports whether the reader made the connection or one is the
// other's ancestor: the credential stayed inside the process tree that read
// it (git-remote-https running gh as its credential helper).
func sameTree(r readMark, cm connMark) bool {
	return r.pid != 0 && (r.pid == cm.pid || slices.Contains(r.chain, cm.pid) || slices.Contains(cm.chain, r.pid))
}

// A file read and connection in unrelated sibling processes are a useful
// temporal lead, but not evidence that the reader sent the bytes. Keep the
// finding for review without a critical OS alarm. A model-visible agent tool
// read remains critical: the model can pass its contents to any child.
func readConnectSeverity(reads []readMark, conns []connMark) int {
	for _, r := range reads {
		if r.kind == event.KindPluginAction {
			return 3
		}
		for _, cm := range conns {
			if !cm.at.Before(r.at) && (r.pid == cm.pid || slices.Contains(cm.chain, r.pid)) {
				return 3
			}
		}
	}
	return 2
}

// readConnectKey is the pattern one read and connection stand for
// (ReadConnectKey).
func readConnectKey(agent string, r readMark, cm connMark) string {
	return ReadConnectKey(agent, ReaderLabel(r.exe, r.kind == event.KindPluginAction), r.path, DestLabel(cm.host))
}

// SetExpected wires the operator's expected patterns: match reports whether
// every key is expected (and counts the hit).
func (c *Correlator) SetExpected(match func(keys []string, at time.Time) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isExpected = match
}

// ExpectedCount counts connections an expected pattern covered (recorded,
// not flagged).
func (c *Correlator) ExpectedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expectedCount
}

// expectedLocked reports whether cm with every read is a pattern the
// operator marked expected.
func (c *Correlator) expectedLocked(agent string, reads []readMark, cm connMark, at time.Time) bool {
	if c.isExpected == nil {
		return false
	}
	keys := make([]string, 0, len(reads))
	for _, r := range reads {
		keys = append(keys, readConnectKey(agent, r, cm))
	}
	return c.isExpected(keys, at)
}

// readThenConnectLocked judges secret reads against connections of one agent
// family. A connection that is every read's credential used with its owner,
// or a pattern the operator marked expected, is counted, not flagged. The rest raise one flag per pattern per
// readRepeatWindow; a repeat folds into the open flag. Callers hold c.mu.
func (c *Correlator) readThenConnectLocked(e event.Event, agent string, rootPID int32, reads []readMark, conns []connMark) []model.Flag {
	var cited []connMark
	for _, cm := range conns {
		switch {
		case c.ownerUse(reads, cm):
			c.ownerUseCount++
		case c.expectedLocked(agent, reads, cm, e.TS):
			c.expectedCount++
		default:
			cited = append(cited, cm)
		}
	}
	if len(cited) == 0 {
		return nil
	}

	// Operator disposition applies only when EVERY cited connection is
	// muted: a fresh unmuted host must still flag.
	if c.isMuted != nil && c.allMutedLocked(agent, cited) {
		c.mutedCount++
		c.markReadConsumedLocked(rootPID, e.PID)
		c.markConnConsumedLocked(rootPID, e.PID)
		return nil
	}

	// One event can cite several reads or destinations. It is a repeat only
	// when every read/destination pair has already raised a recent flag; a
	// new secret or destination must never disappear behind reads[0].
	keys := make([]string, 0, len(reads)*len(cited))
	seen := make(map[string]bool, len(reads)*len(cited))
	severity := readConnectSeverity(reads, cited)
	allRepeated := true
	openChecks := map[string]bool{}
	checked := map[string]bool{}
	repeatID := ""
	for _, r := range reads {
		for _, cm := range cited {
			key := readConnectKey(agent, r, cm)
			if seen[key] {
				continue
			}
			seen[key] = true
			keys = append(keys, key)
			prev, ok := c.folded[key]
			active := ok && e.TS.Sub(prev.at) >= 0 && e.TS.Sub(prev.at) < readRepeatWindow
			if ok && c.isOpenFlag != nil {
				if !checked[prev.id] {
					openChecks[prev.id] = c.isOpenFlag(prev.id)
					checked[prev.id] = true
				}
				active = openChecks[prev.id]
			}
			if !active || severity > prev.severity {
				allRepeated = false
			} else if repeatID == "" {
				repeatID = prev.id
			}
		}
	}
	if allRepeated {
		c.markReadConsumedLocked(rootPID, e.PID)
		c.markConnConsumedLocked(rootPID, e.PID)
		c.repeats = append(c.repeats, flagRepeat{id: repeatID, at: e.TS})
		return nil
	}

	var evidence []model.EvidenceItem
	for _, r := range reads {
		sub := "sensitive read"
		if r.kind == event.KindPluginAction {
			sub = "agent tool read"
		}
		evidence = append(evidence, model.EvidenceItem{
			Kind:   "read",
			Label:  r.path,
			Sub:    sub,
			Rule:   r.rule,
			TS:     r.at.Format(time.RFC3339),
			Text:   fmt.Sprintf("%s (pid %d) read %s at %s", agent, r.pid, r.path, r.at.Format(time.RFC3339)),
			PID:    r.pid,
			Chain:  append([]int32(nil), r.chain...),
			Exe:    r.exe,
			Owners: c.credentialOwners(r.path),
		})
	}
	for _, cm := range cited {
		evidence = append(evidence, model.EvidenceItem{
			Kind:  "connect",
			Label: fmt.Sprintf("%s:%d", cm.host, cm.port),
			Sub:   "egress",
			TS:    cm.at.Format(time.RFC3339),
			Text:  fmt.Sprintf("connection observed to %s:%d at %s", cm.host, cm.port, cm.at.Format(time.RFC3339)),
			PID:   cm.pid,
			Exe:   cm.exe,
			Chain: append([]int32(nil), cm.chain...),
		})
	}
	id := hashFlagID(readConnectRule, rootPID, reads[0].at)
	for _, key := range keys {
		c.foldLocked(key, id, e.TS, severity)
	}
	c.markReadConsumedLocked(rootPID, e.PID)
	c.markConnConsumedLocked(rootPID, e.PID)
	return []model.Flag{{
		ID:        id,
		Rule:      readConnectRule,
		Severity:  severity,
		TS:        e.TS,
		PID:       e.PID,
		Agent:     agent,
		SessionID: e.SessionID,
		Evidence:  evidence,
	}}
}

func (c *Correlator) allMutedLocked(agent string, conns []connMark) bool {
	for _, cm := range conns {
		h := cm.host
		if isLocalhost(h) {
			h = "localhost" // canonical alias: one mute covers the family
		}
		if !c.isMuted(readConnectRule, h, agent) {
			return false
		}
	}
	return true
}

// foldLocked records the flag a pattern raised; entries past the window are
// pruned once the map passes 1,024 keys.
func (c *Correlator) foldLocked(key, id string, at time.Time, severity int) {
	if c.folded == nil {
		c.folded = map[string]foldedFlag{}
	}
	c.folded[key] = foldedFlag{id: id, at: at, severity: severity}
	if len(c.folded) > 1024 {
		for k, f := range c.folded {
			if at.Sub(f.at) >= readRepeatWindow {
				delete(c.folded, k)
			}
		}
	}
}

// SetOpenFlagChecker keeps an unresolved finding folded across hourly windows.
// When unwired, the bounded in-memory window remains the fallback.
func (c *Correlator) SetOpenFlagChecker(check func(string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isOpenFlag = check
}

// StoredReadConnectSeverity re-evaluates causal strength from recorded
// evidence only. Missing legacy process IDs retain their original severity.
func StoredReadConnectSeverity(f model.Flag) int {
	var reads []readMark
	var conns []connMark
	for _, ev := range f.Evidence {
		at, _ := time.Parse(time.RFC3339, ev.TS)
		switch ev.Kind {
		case "read":
			if ev.Sub == "agent tool read" {
				return 3
			}
			if ev.PID == 0 {
				return f.Severity
			}
			reads = append(reads, readMark{pid: ev.PID, at: at, chain: ev.Chain})
		case "connect":
			if ev.PID == 0 {
				return f.Severity
			}
			conns = append(conns, connMark{pid: ev.PID, at: at, chain: ev.Chain})
		}
	}
	if len(reads) == 0 || len(conns) == 0 {
		return f.Severity
	}
	return readConnectSeverity(reads, conns)
}

// RestoreOpenReadFlags seeds folding from persisted unresolved findings.
// Input is newest first; stronger prior evidence must not be overwritten.
func (c *Correlator) RestoreOpenReadFlags(flags []model.Flag) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range flags {
		if f.Acknowledged || f.Rule != readConnectRule {
			continue
		}
		for _, r := range f.Evidence {
			if r.Kind != "read" {
				continue
			}
			for _, cm := range f.Evidence {
				if cm.Kind != "connect" {
					continue
				}
				host := cm.Label
				// Evidence includes a port, including legacy unbracketed IPv6.
				if i := strings.LastIndex(host, ":"); i >= 0 {
					host = strings.Trim(host[:i], "[]")
				}
				key := ReadConnectKey(f.Agent, ReaderLabel(r.Exe, r.Sub == "agent tool read"), r.Label, DestLabel(host))
				prev, ok := c.folded[key]
				if !ok || f.Severity > prev.severity {
					c.foldLocked(key, f.ID, f.TS, f.Severity)
				}
			}
		}
	}
}
