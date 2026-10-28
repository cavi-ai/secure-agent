package correlate

import (
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const untrustedEgressRule = "untrusted-egress"

// untrustedRepeatWindow: without OpenFlag, later sends from one session fold
// into its untrusted-egress flag for this long.
const untrustedRepeatWindow = time.Hour

// untrustedEgressLocked raises one flag per session for the sends the guard
// hook reported after the session read untrusted content. A later send of the
// same or lower severity folds into the open flag. Callers hold c.mu.
func (c *Correlator) untrustedEgressLocked(e event.Event) []model.Flag {
	u, ok := e.Untrusted.Clean()
	if !ok || e.SessionID == "" {
		return nil
	}
	agent := u.Harness
	if info, isAgent := c.tagger.Tag(e.PID); isAgent {
		agent = info.Name
	}
	if agent == "" {
		agent = "agent"
	}
	if c.isMuted != nil && c.isMuted(untrustedEgressRule, "*", agent) {
		c.mutedCount++
		return nil
	}
	severity := 1
	if u.Decision == "monitored" || u.Decision == "asked" {
		severity = 2
	}
	key := untrustedEgressRule + "|" + e.SessionID
	if prev, ok := c.folded[key]; ok && severity <= prev.severity {
		active := e.TS.Sub(prev.at) >= 0 && e.TS.Sub(prev.at) < untrustedRepeatWindow
		if c.isOpenFlag != nil {
			active = c.isOpenFlag(prev.id)
		}
		if active {
			c.repeats = append(c.repeats, flagRepeat{id: prev.id, at: e.TS})
			return nil
		}
	}
	evidence := make([]model.EvidenceItem, 0, len(u.Sources)+1)
	for _, s := range u.Sources {
		label := model.UntrustedKindLabel(s.Kind) + ": " + s.Location
		origin := s.Origin
		if origin == "" {
			origin = "no recorded origin"
		}
		evidence = append(evidence, model.EvidenceItem{
			Kind:  "untrusted-input",
			Label: label,
			Sub:   origin,
			Rule:  s.Kind,
			TS:    rfc3339(s.TS),
			Text:  fmt.Sprintf("%s read %s (%s)", agent, label, origin),
		})
	}
	decision := model.UntrustedDecisionLabel(u.Decision)
	evidence = append(evidence, model.EvidenceItem{
		Kind:  "send",
		Label: u.Sinks,
		Sub:   decision,
		Rule:  u.Decision,
		TS:    e.TS.Format(time.RFC3339),
		Text:  fmt.Sprintf("%s then sent data out through %s: %s", agent, u.Sinks, decision),
	})
	id := hashFlagID(key, 0, e.TS)
	previous, existed := c.folded[key]
	c.recordPersistenceUndoLocked(id, func() {
		if existed {
			c.folded[key] = previous
		} else {
			delete(c.folded, key)
		}
	})
	c.foldLocked(key, id, e.TS, severity)
	return []model.Flag{{
		ID:        id,
		Rule:      untrustedEgressRule,
		Severity:  severity,
		TS:        e.TS,
		PID:       e.PID,
		Agent:     agent,
		SessionID: e.SessionID,
		Evidence:  evidence,
	}}
}

// rfc3339 normalizes a hook timestamp, or returns "" when it does not parse.
func rfc3339(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
