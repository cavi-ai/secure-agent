package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// RunEnding is how a daemon run ended, as written to its run record.
type RunEnding string

const (
	// RunEndingOwnerStop is a SIGTERM or SIGINT inside StopIntentWindow after a stop intent.
	RunEndingOwnerStop RunEnding = "owner-stop"
	// RunEndingSignal is a SIGTERM or SIGINT with no valid stop intent.
	RunEndingSignal RunEnding = "signal"
	// RunEndingParentExit is the owning parent process going away.
	RunEndingParentExit RunEnding = "parent-exit"
	// RunEndingAPIFailure is the control API stopping unexpectedly.
	RunEndingAPIFailure RunEnding = "api-failure"
	// RunEndingStartFailure is Shutdown with no stop trigger: Build failed after the run started.
	RunEndingStartFailure RunEnding = "start-failure"
	// RunEndingNoRecord is a run whose record has a running marker and no ending.
	RunEndingNoRecord RunEnding = "no-record"
	// RunEndingUnconfirmedStop is a record that reports an owner stop for a run
	// the event store holds no stop intent for.
	RunEndingUnconfirmedStop RunEnding = "unconfirmed-owner-stop"
)

// StopIntentWindow is how long a stop intent stays valid: a signal later than
// this after the intent ends the run as RunEndingSignal.
const StopIntentWindow = 30 * time.Second

const runRecordSuffix = ".run-record.json"

// RunRecord is one daemon run as persisted in the state directory. A record
// with an empty Ending is the running marker of a run that has not ended.
type RunRecord struct {
	PID          int       `json:"pid"`
	StartedAt    time.Time `json:"started_at"`
	StopIntentAt time.Time `json:"stop_intent_at,omitzero"`
	EndedAt      time.Time `json:"ended_at,omitzero"`
	Ending       RunEnding `json:"ending,omitempty"`
}

// PreviousRun is a persisted run record and how that run ended.
type PreviousRun struct {
	Record RunRecord `json:"record"`
	Ending RunEnding `json:"ending"`
}

type pendingRun struct {
	PreviousRun
	// ObservedAt identifies a record with no readable start time across retries.
	ObservedAt time.Time `json:"observed_at,omitzero"`
}

// runState keeps the current marker and unresolved evidence in one atomic write.
// Older files have only the embedded RunRecord fields.
type runState struct {
	RunRecord
	Pending []pendingRun `json:"pending,omitempty"`
}

// RunRecordPath scopes the run record to the same database as the instance
// lock, or to the socket when the store is in-memory.
func RunRecordPath(cfg config.Config) string {
	if cfg.DBPath != "" {
		return cfg.DBPath + runRecordSuffix
	}
	if cfg.SocketPath != "" {
		return cfg.SocketPath + runRecordSuffix
	}
	return ""
}

// ReadPreviousRun reads the run record at path. found is false when no record
// exists; a record without an ending reads as RunEndingNoRecord.
func ReadPreviousRun(path string) (prev PreviousRun, found bool, err error) {
	state, found, err := readRunState(path)
	if !found {
		return PreviousRun{}, false, err
	}
	return previousRun(state.RunRecord), true, nil
}

func readRunState(path string) (runState, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return runState{}, false, nil
	}
	if err != nil {
		return runState{}, false, err
	}
	var state runState
	if err := json.Unmarshal(data, &state); err != nil {
		return runState{}, false, fmt.Errorf("run record %s: %w", path, err)
	}
	return state, true, nil
}

func previousRun(rec RunRecord) PreviousRun {
	ending := rec.Ending
	if ending == "" {
		ending = RunEndingNoRecord
	}
	return PreviousRun{Record: rec, Ending: ending}
}

// RunTracker owns the current run's record: the running marker written at
// start, the owner's stop intent, and the ending written once at stop.
type RunTracker struct {
	path string
	now  func() time.Time

	mu              sync.Mutex
	rec             RunRecord
	pending         []pendingRun
	endingPersisted bool
	// ownerStop is the previous run when its record reports an owner stop;
	// raisePreviousRunFindings confirms it against the event store.
	ownerStop *RunRecord
}

// StartRun writes this run's running marker and carries forward any previous
// run evidence that may still need a finding. The tracker is usable even
// when the write fails; the error reports the unwritten marker.
func StartRun(path string, pid int, now func() time.Time) (*RunTracker, error) {
	t := &RunTracker{path: path, now: now, rec: RunRecord{PID: pid, StartedAt: now().UTC()}}
	state, found, err := readRunState(path)
	if err != nil {
		// An unreadable record cannot show an ending.
		log.Printf("secure-agentd: previous run record unreadable: %v", err)
		found = true
	}
	t.pending = state.Pending
	if found && state.Ending != RunEndingOwnerStop {
		pending := pendingRun{PreviousRun: previousRun(state.RunRecord)}
		if pending.Record.StartedAt.IsZero() {
			pending.ObservedAt = t.rec.StartedAt
		}
		t.pending = append(t.pending, pending)
	}
	if found && state.Ending == RunEndingOwnerStop {
		rec := state.RunRecord
		t.ownerStop = &rec
	}
	return t, t.write(t.rec)
}

// RecordStopIntent notes that the owner is about to stop the daemon and
// returns when the intent was recorded and until when it counts.
func (t *RunTracker) RecordStopIntent() (at, validUntil time.Time, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	at = t.now().UTC()
	if t.rec.Ending != "" {
		return at, at, fmt.Errorf("run already ended: %s", t.rec.Ending)
	}
	rec := t.rec
	rec.StopIntentAt = at
	if err := t.write(rec); err != nil {
		return at, at, err
	}
	t.rec = rec
	return at, at.Add(StopIntentWindow), nil
}

// Stop durably writes this run's ending for the stop trigger cause and
// returns it. Later calls keep the first ending and retry any failed write.
func (t *RunTracker) Stop(cause RunEnding) (RunEnding, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.endingPersisted {
		return t.rec.Ending, nil
	}
	if t.rec.Ending == "" {
		at := t.now().UTC()
		ending := cause
		if cause == RunEndingSignal && !t.rec.StopIntentAt.IsZero() && !at.Before(t.rec.StopIntentAt) && at.Sub(t.rec.StopIntentAt) <= StopIntentWindow {
			ending = RunEndingOwnerStop
		}
		t.rec.EndedAt, t.rec.Ending = at, ending
	}
	if err := t.write(t.rec); err != nil {
		return t.rec.Ending, err
	}
	t.endingPersisted = true
	return t.rec.Ending, nil
}

// write persists the candidate record with fsync before rename.
func (t *RunTracker) write(rec RunRecord) error {
	data, err := json.Marshal(runState{RunRecord: rec, Pending: t.pending})
	if err != nil {
		return err
	}
	return safefile.WriteFileAtomic(t.path, data, 0o600)
}
