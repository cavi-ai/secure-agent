package correlate

import (
	"fmt"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// stateWriteRule reports an agent changing a file in the daemon's state
// directory: the event store, the run record and the collectors' positions.
const stateWriteRule = "monitor-state-write"

// hookStatePath reports whether rel, a path inside the state directory, is
// one the hooks write from inside agent process trees: the activity log and
// the session markers.
func hookStatePath(rel string) bool {
	return rel == "activity.jsonl" || rel == "sessions_seen" || strings.HasPrefix(rel, "sessions_seen/")
}

// stateWriteLocked applies the monitor-state-write rule to one file event
// attributed to agent: a write, a delete or an open for writing of a path in
// the state directory that the hooks do not write. Callers hold c.mu.
func (c *Correlator) stateWriteLocked(e event.Event, agent string) []model.Flag {
	if c.stateDir == "" {
		return nil
	}
	var did string
	switch e.Kind {
	case event.KindFileWrite:
		if e.RenameSource != "" && e.RenameSource != e.Path {
			flags := c.stateWritePathLocked(e, agent, e.Path, "renamed to")
			return append(flags, c.stateWritePathLocked(e, agent, e.RenameSource, "renamed from")...)
		}
		did = "wrote"
	case event.KindFileDelete:
		did = "deleted"
	case event.KindFileOpen:
		if !e.OpensForWrite() {
			return nil
		}
		did = "opened for writing"
	default:
		return nil
	}
	return c.stateWritePathLocked(e, agent, e.Path, did)
}

func (c *Correlator) stateWritePathLocked(e event.Event, agent, path, did string) []model.Flag {
	rel, inside := strings.CutPrefix(path, strings.TrimSuffix(c.stateDir, "/")+"/")
	if (!inside && path != c.stateDir) || hookStatePath(rel) {
		return nil
	}
	flagID := hashFlagID(stateWriteRule+"|"+path, e.PID, e.TS)
	if !c.shouldFlag(flagID, stateWriteRule, e.PID, path, e.TS, repeatWindows[stateWriteRule]) {
		return nil
	}
	at := e.TS.Format(time.RFC3339)
	return []model.Flag{{
		ID:        flagID,
		Rule:      stateWriteRule,
		Severity:  3,
		TS:        e.TS,
		PID:       e.PID,
		Agent:     agent,
		SessionID: e.SessionID,
		Evidence: []model.EvidenceItem{{
			Kind:  "file",
			Label: path,
			Sub:   "monitor state file",
			TS:    at,
			Text:  fmt.Sprintf("%s (pid %d) %s %s in the monitor's state directory at %s", agent, e.PID, did, path, at),
		}},
	}}
}
