package daemon

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// monitorStoppedRule reports a previous run with no recorded owner stop.
const monitorStoppedRule = "monitor-stopped"

// monitorAgent names the daemon as the reporter of its own previous run.
const monitorAgent = "secure-agentd"

// raisePreviousRunFindings processes persisted records after the store opens.
// Keep any failed inserts pending for the next start.
func raisePreviousRunFindings(st *store.Store, run *RunTracker, bootTime func() (time.Time, error), now func() time.Time) {
	if st == nil || run == nil {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if len(run.pending) == 0 {
		return
	}
	boot, bootErr := bootTime()
	if bootErr != nil {
		log.Printf("secure-agentd: boot time unreadable: %v", bootErr)
	}
	var remaining []pendingRun
	for _, pending := range run.pending {
		started := pending.Record.StartedAt
		if bootErr == nil && !started.IsZero() && started.Before(boot) {
			continue
		}
		finding := pending
		if pending.Ending == RunEndingOwnerStop {
			if ownerStopConfirmed(st, pending.Record) {
				continue
			}
			finding.Ending = RunEndingUnconfirmedStop
		}
		if err := storePreviousRunFinding(st, finding, now); err != nil {
			log.Printf("secure-agentd: %s finding not stored: %v", monitorStoppedRule, err)
			remaining = append(remaining, pending)
		}
	}
	if len(remaining) == len(run.pending) {
		return
	}
	run.pending = remaining
	if err := run.write(run.rec); err != nil {
		// A retry can recognize findings already in the store by their stable IDs.
		log.Printf("secure-agentd: pending run records not updated: %v", err)
	}
}

// ownerStopConfirmed reports whether the store agrees that rec ended by an
// owner stop: it holds a valid stop intent for the run, or it holds no runs at all
// (a store written before runs were recorded).
func ownerStopConfirmed(st *store.Store, rec RunRecord) bool {
	intent, found, err := st.MonitorRunStopIntent(rec.PID, rec.StartedAt)
	if err != nil {
		log.Printf("secure-agentd: stored run unreadable: %v", err)
		return false
	}
	if found {
		return stopIntentValidAt(intent, rec.EndedAt)
	}
	has, err := st.HasMonitorRuns()
	if err != nil {
		log.Printf("secure-agentd: stored runs unreadable: %v", err)
		return false
	}
	return !has
}

// recordRunStart stores this run's pid and start time so a later start can
// confirm how the run ended.
func recordRunStart(st *store.Store, run *RunTracker) {
	if st == nil || run == nil {
		return
	}
	run.mu.Lock()
	pid, started := run.rec.PID, run.rec.StartedAt
	run.mu.Unlock()
	if err := st.PutMonitorRun(pid, started); err != nil {
		log.Printf("secure-agentd: run start not stored: %v", err)
	}
}

// recordStopIntent records the owner's stop intent in the run record and in
// the event store.
func recordStopIntent(st *store.Store, run *RunTracker) (at, validUntil time.Time, err error) {
	if st == nil || run == nil {
		return time.Time{}, time.Time{}, errors.New("run record or event store unavailable")
	}
	return run.recordStopIntent(func(rec RunRecord) error {
		if err := st.PutMonitorStopIntent(rec.PID, rec.StartedAt, rec.StopIntentAt); err != nil {
			return fmt.Errorf("store stop intent: %w", err)
		}
		return nil
	})
}

func storePreviousRunFinding(st *store.Store, pending pendingRun, now func() time.Time) error {
	prev := pending.PreviousRun
	key := prev.Record.StartedAt
	if key.IsZero() {
		key = pending.ObservedAt
	}
	id := correlate.FlagID(fmt.Sprintf("%s|%s|%d", monitorStoppedRule, prev.Ending, prev.Record.PID), 0, key)
	if _, exists, err := st.GetFlag(id); err != nil || exists {
		return err
	}
	fl := previousRunFlag(id, prev, now().UTC())
	if _, err := st.PutFlag(fl); err != nil {
		return err
	}
	log.Printf("FLAG TRIGGERED [%d]: %s (previous run ending %s)", fl.Severity, fl.Rule, prev.Ending)
	return nil
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
			Kind:  model.EvidenceKindMonitorRun,
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
	case RunEndingUnconfirmedStop:
		return "owner stop with no valid stored stop intent", "was recorded as an owner stop with no valid stored stop intent"
	default:
		return string(ending), "ended as " + string(ending)
	}
}
