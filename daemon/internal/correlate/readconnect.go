package correlate

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const readConnectRule = "sensitive-read-then-connect"

// readRepeatWindow: one read-then-connect pattern (agent, reader, secret,
// destination org) raises one flag per window; repeats fold into it.
const readRepeatWindow = 60 * time.Minute

type foldedFlag struct {
	id string
	at time.Time
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
// process tree, and an org that owns the file is the destination. Other
// processes reading the same file do not change that. An agent tool read
// never qualifies: it put the file into the model's context.
func (c *Correlator) ownerUse(reads []readMark, cm connMark) bool {
	org := IdentifyCached(cm.host).Org
	if org == "" || cm.pid == 0 || len(reads) == 0 {
		return false
	}
	explained := map[string]bool{}
	for _, r := range reads {
		ok := r.kind == event.KindFileOpen && sameTree(r, cm) && slices.Contains(c.credentialOwners(r.path), org)
		explained[r.path] = explained[r.path] || ok
	}
	for _, ok := range explained {
		if !ok {
			return false
		}
	}
	return true
}

// sameTree reports whether the reader made the connection or one is the
// other's ancestor: the credential stayed inside the process tree that read
// it (git-remote-https running gh as its credential helper).
func sameTree(r readMark, cm connMark) bool {
	return r.pid != 0 && (r.pid == cm.pid || slices.Contains(r.chain, cm.pid) || slices.Contains(cm.chain, r.pid))
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

	key := readConnectKey(agent, reads[0], cited[0])
	if prev, ok := c.folded[key]; ok && e.TS.Sub(prev.at) >= 0 && e.TS.Sub(prev.at) < readRepeatWindow {
		c.markReadConsumedLocked(rootPID, e.PID)
		c.markConnConsumedLocked(rootPID, e.PID)
		c.repeats = append(c.repeats, flagRepeat{id: prev.id, at: e.TS})
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
			Text:  fmt.Sprintf("then connected to %s:%d at %s", cm.host, cm.port, cm.at.Format(time.RFC3339)),
			PID:   cm.pid,
		})
	}
	id := hashFlagID(readConnectRule, rootPID, reads[0].at)
	c.foldLocked(key, id, e.TS)
	c.markReadConsumedLocked(rootPID, e.PID)
	c.markConnConsumedLocked(rootPID, e.PID)
	return []model.Flag{{
		ID:        id,
		Rule:      readConnectRule,
		Severity:  3,
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
func (c *Correlator) foldLocked(key, id string, at time.Time) {
	if c.folded == nil {
		c.folded = map[string]foldedFlag{}
	}
	c.folded[key] = foldedFlag{id: id, at: at}
	if len(c.folded) > 1024 {
		for k, f := range c.folded {
			if at.Sub(f.at) >= readRepeatWindow {
				delete(c.folded, k)
			}
		}
	}
}
