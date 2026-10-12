package api

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// statusEvidenceStore supplies the stored facts joined onto live status.
type statusEvidenceStore interface {
	LastEventTimes([]int32) map[int32]string
	SessionsByRootPID() map[int32]model.Session
	QueryFlags(store.FlagFilter) ([]model.Flag, error)
}

// joinStatusEvidence stamps each agent's last event, groups agents into trees
// labelled from their root's durable session, and counts the last day's
// unacted findings. Live process facts are never overwritten.
func joinStatusEvidence(st statusEvidenceStore, s Status, now time.Time) Status {
	if len(s.Agents) > 0 {
		pids := make([]int32, len(s.Agents))
		for i, ag := range s.Agents {
			pids[i] = ag.PID
		}
		times := st.LastEventTimes(pids)
		for i := range s.Agents {
			if ts, ok := times[s.Agents[i].PID]; ok {
				s.Agents[i].LastSeenAt = ts
			}
		}
	}
	s.Trees = GroupAgentTrees(s.Agents)
	// Join each tree root to its durable session (by root pid) so the menubar
	// and console can label a row with the harness + repo@branch the session
	// knows — the process cwd alone reads as "/" for many agents.
	if byRoot := st.SessionsByRootPID(); len(byRoot) > 0 {
		for i := range s.Trees {
			root := &s.Trees[i].Root
			pid := root.RootPID
			if pid == 0 {
				pid = root.PID
			}
			if sess, ok := byRoot[pid]; ok {
				if root.SessionID == "" {
					root.SessionID = sess.ID
				}
				if root.Workspace == "" {
					root.Workspace = sess.Workspace
				}
				if root.Repo == "" {
					root.Repo = sess.Repo
				}
				if root.Branch == "" {
					root.Branch = sess.Branch
				}
				if root.Origin == "" {
					root.Origin = sess.Origin
				}
			}
		}
	}
	flags, err := st.QueryFlags(store.FlagFilter{
		Unacted:     true,
		MinSeverity: 2,
		Since:       now.Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		Limit:       500,
	})
	if err == nil {
		s.UnactedFlags24h = len(flags)
	}
	return s
}
