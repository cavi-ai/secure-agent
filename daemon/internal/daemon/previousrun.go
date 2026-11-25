package daemon

import (
	"fmt"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// monitorStoppedRule is the finding for a previous run that ended without an
// owner stop in the current boot.
const monitorStoppedRule = "monitor-stopped"

// monitorAgent names the daemon as the reporter of its own previous run.
const monitorAgent = "secure-agentd"

// raisePreviousRunFinding stores one monitor-stopped finding when the run
// before run ended without an owner stop since the machine booted. A run that
// started before the boot time raises nothing; an unreadable boot time does
// not prevent the finding. Each previous run is stored at most once.
func raisePreviousRunFinding(st *store.Store, run *RunTracker, bootTime func() (time.Time, error), now func() time.Time) {
	if st == nil || run == nil {
		return
	}
	prev, found := run.Previous()
	if !found || prev.Ending == RunEndingOwnerStop {
		return
	}
	started := prev.Record.StartedAt
	if !started.IsZero() {
		boot, err := bootTime()
		if err != nil {
			log.Printf("secure-agentd: boot time unreadable: %v", err)
		} else if started.Before(boot) {
			return
		}
	}
	key := started
	if key.IsZero() {
		// An unreadable record has no start time: the finding is keyed to this run.
		run.mu.Lock()
		key = run.rec.StartedAt
		run.mu.Unlock()
	}
	id := correlate.FlagID(fmt.Sprintf("%s|%s|%d", monitorStoppedRule, prev.Ending, prev.Record.PID), 0, key)
	if _, exists, err := st.GetFlag(id); err == nil && exists {
		return
	}
	fl := previousRunFlag(id, prev, now().UTC())
	if _, err := st.PutFlag(fl); err != nil {
		log.Printf("secure-agentd: %s finding not stored: %v", monitorStoppedRule, err)
		return
	}
	log.Printf("FLAG TRIGGERED [%d]: %s (previous run ending %s)", fl.Severity, fl.Rule, prev.Ending)
}

// previousRunFlag is the severity-3 finding for prev, detected at at. Its text
// names how the run ended and its start and end times from the record.
func previousRunFlag(id string, prev PreviousRun, at time.Time) model.Flag {
	rec := prev.Record
	sub, how := runEndingPhrase(prev.Ending)
	var ts, text string
	switch {
	case rec.StartedAt.IsZero():
		ts = at.Format(time.RFC3339)
		text = "The previous monitor run's record could not be read: its start, end and ending are unknown."
	case rec.EndedAt.IsZero():
		ts = rec.StartedAt.Format(time.RFC3339)
		text = fmt.Sprintf("Monitor run pid %d started at %s and %s.", rec.PID, ts, how)
	default:
		ts = rec.EndedAt.Format(time.RFC3339)
		text = fmt.Sprintf("Monitor run pid %d started at %s and %s at %s.", rec.PID, rec.StartedAt.Format(time.RFC3339), how, ts)
	}
	return model.Flag{
		ID:       id,
		Rule:     monitorStoppedRule,
		Severity: 3,
		TS:       at,
		Agent:    monitorAgent,
		Evidence: []model.EvidenceItem{{
			Kind:  "monitor-run",
			Label: string(prev.Ending),
			Sub:   sub,
			TS:    ts,
			Text:  text,
		}},
	}
}

// runEndingPhrase returns a label and a sentence fragment for an ending other
// than an owner stop.
func runEndingPhrase(ending RunEnding) (sub, how string) {
	switch ending {
	case RunEndingSignal:
		return "signal with no stop intent", "was stopped by a signal with no stop intent"
	case RunEndingParentExit:
		return "owning app exited", "stopped when its owning app process exited"
	case RunEndingAPIFailure:
		return "control API failure", "stopped after its control API failed"
	case RunEndingStartFailure:
		return "start failure", "failed during start"
	case RunEndingNoRecord:
		return "no ending recorded", "ended with no ending recorded"
	default:
		return string(ending), "ended as " + string(ending)
	}
}
