package correlate

import (
	"fmt"
	"path/filepath"
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

// ownerUse reports whether cm is every read's credential used with its
// owner: the process that opened each file made the connection, and an org
// that owns the credential is the destination. An agent tool read never
// qualifies: it put the file into the model's context.
func (c *Correlator) ownerUse(reads []readMark, cm connMark) bool {
	org := IdentifyCached(cm.host).Org
	if org == "" || cm.pid == 0 {
		return false
	}
	for _, r := range reads {
		if r.kind != event.KindFileOpen || r.pid != cm.pid || !slices.Contains(c.credentialOwners(r.path), org) {
			return false
		}
	}
	return true
}

// readConnectKey is the pattern one flag stands for: agent, the reader's
// executable, the first secret read, and the first destination's org (its
// host when the org is unknown).
func readConnectKey(agent string, r readMark, cm connMark) string {
	reader := "tool"
	if r.kind != event.KindPluginAction {
		reader = strings.ToLower(filepath.Base(r.exe))
	}
	dest := IdentifyCached(cm.host).Org
	if dest == "" {
		dest = strings.ToLower(cm.host)
	}
	return agent + "|" + reader + "|" + r.path + "|" + dest
}

// readThenConnectLocked judges secret reads against connections of one agent
// family. A connection that is every read's credential used with its owner
// is counted, not flagged. The rest raise one flag per pattern per
// readRepeatWindow; a repeat folds into the open flag. Callers hold c.mu.
func (c *Correlator) readThenConnectLocked(e event.Event, agent string, rootPID int32, reads []readMark, conns []connMark) []model.Flag {
	var cited []connMark
	for _, cm := range conns {
		if c.ownerUse(reads, cm) {
			c.ownerUseCount++
			continue
		}
		cited = append(cited, cm)
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
		evidence = append(evidence, model.EvidenceItem{
			Kind:  "read",
			Label: r.path,
			Sub:   "sensitive read",
			Rule:  r.rule,
			TS:    r.at.Format(time.RFC3339),
			Text:  fmt.Sprintf("%s (pid %d) read %s at %s", agent, r.pid, r.path, r.at.Format(time.RFC3339)),
			PID:   r.pid,
			Exe:   r.exe,
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
