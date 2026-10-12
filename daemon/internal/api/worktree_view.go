package api

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentask"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

type cleanupTotalsReader interface {
	CleanupTotals(time.Time) model.CleanupTotals
}

type agentAskReader interface {
	AgentAsks(int) []model.AgentAsk
}

type activeSessionReader interface {
	ListSessionsResult(store.SessionFilter) ([]model.Session, error)
}

// worktreeReportStore supplies the stored context shown beside scanned rows.
type worktreeReportStore interface {
	advisorVerdictsReader
	cleanupTotalsReader
	agentAskReader
	activeSessionReader
}

// enrichWorktreeReport adds advisor notes, the latest agent asks, the rows
// whose agent can be asked, and reclaimed space. rep is the handler's copy.
func enrichWorktreeReport(st worktreeReportStore, rep worktreehunter.ScanReport, canAsk bool, now time.Time) worktreehunter.ScanReport {
	rep.Advice = worktreeNotes(st, rep)
	rep.Asks = latestAsks(st)
	if canAsk {
		rep.Askable = askableWorktrees(st, rep)
	}
	t := st.CleanupTotals(now)
	rep.Reclaimed = &t
	return rep
}

// worktreeNotes looks up the stored advisor note for each row at its current
// HEAD. The returned map is new; the scan is not modified.
func worktreeNotes(reader advisorVerdictsReader, rep worktreehunter.ScanReport) map[string]model.AdvisorVerdict {
	var paths, subjectIDs []string
	for _, repo := range rep.Repos {
		for _, wt := range repo.Worktrees {
			if wt.Head == "" || wt.State == worktreehunter.StateMain {
				continue
			}
			paths = append(paths, wt.Path)
			subjectIDs = append(subjectIDs, advisor.WorktreeSubjectID(wt.Path, wt.Head))
		}
	}
	// Optional notes may be partial; retain read health for the whole batch.
	verdicts, _ := reader.AdvisorVerdictsFor(subjectIDs, "worktree")
	notes := make(map[string]model.AdvisorVerdict, len(verdicts))
	for i, subject := range subjectIDs {
		if v, ok := verdicts[subject]; ok {
			notes[paths[i]] = v
		}
	}
	if len(notes) == 0 {
		return nil
	}
	return notes
}

// latestAsks maps each worktree path to its newest agent ask.
func latestAsks(st agentAskReader) map[string]model.AgentAsk {
	out := map[string]model.AgentAsk{}
	for _, ask := range st.AgentAsks(500) {
		if _, seen := out[ask.Path]; !seen {
			out[ask.Path] = ask
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// askableWorktrees names the harness of a live, identified session working
// inside each keep or review row. A failed session read offers no row.
func askableWorktrees(st activeSessionReader, rep worktreehunter.ScanReport) map[string]string {
	sessions, err := st.ListSessionsResult(store.SessionFilter{Status: model.SessionActive, Limit: 10000})
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, repo := range rep.Repos {
		for _, wt := range repo.Worktrees {
			if !wt.InUse || (wt.State != worktreehunter.StateKeep && wt.State != worktreehunter.StateReview) || wt.Orphan {
				continue
			}
			for _, sess := range sessions {
				if !agentask.EligibleSession(sess) {
					continue
				}
				rel, err := filepath.Rel(wt.Path, sess.Workspace)
				if err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					out[wt.Path] = sess.Harness
					break
				}
			}
		}
	}
	return out
}

// cleanupLedgerStore is the cleanup ledger: removals, totals and daily sums.
type cleanupLedgerStore interface {
	cleanupTotalsReader
	CleanupLog(int) []model.CleanupEntry
	CleanupDaily(time.Time, int) []model.CleanupDay
}

// readCleanupLedger returns the newest limit entries with all-time and 30-day
// totals, plus the daily series of the days ending today when days > 0.
func readCleanupLedger(st cleanupLedgerStore, now time.Time, limit, days int) map[string]any {
	out := map[string]any{
		"totals":  st.CleanupTotals(now),
		"entries": st.CleanupLog(limit),
	}
	if days > 0 {
		out["daily"] = st.CleanupDaily(now, days)
	}
	return out
}
