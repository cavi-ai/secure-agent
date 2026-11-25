package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
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
)

// StopIntentWindow is how long a stop intent stays valid: a signal later than
// this after the intent ends the run as RunEndingSignal.
const StopIntentWindow = 30 * time.Second

const runRecordName = "run-record.json"

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
	Record RunRecord
	Ending RunEnding
}

// RunRecordPath is the run record beside the daemon's other state files.
func RunRecordPath(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), runRecordName)
}

// ReadPreviousRun reads the run record at path. found is false when no record
// exists; a record without an ending reads as RunEndingNoRecord.
func ReadPreviousRun(path string) (prev PreviousRun, found bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return PreviousRun{}, false, nil
	}
	if err != nil {
		return PreviousRun{}, false, err
	}
	var rec RunRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return PreviousRun{}, false, fmt.Errorf("run record %s: %w", path, err)
	}
	ending := rec.Ending
	if ending == "" {
		ending = RunEndingNoRecord
	}
	return PreviousRun{Record: rec, Ending: ending}, true, nil
}

// RunTracker owns the current run's record: the running marker written at
// start, the owner's stop intent, and the ending written once at stop.
type RunTracker struct {
	path     string
	now      func() time.Time
	previous PreviousRun
	found    bool

	mu  sync.Mutex
	rec RunRecord
}

// StartRun reads the previous run's record at path, then durably replaces it
// with this run's running marker. The tracker is usable even when the write
// fails; the error reports the unwritten marker.
func StartRun(path string, pid int, now func() time.Time) (*RunTracker, error) {
	t := &RunTracker{path: path, now: now, rec: RunRecord{PID: pid, StartedAt: now().UTC()}}
	prev, found, err := ReadPreviousRun(path)
	if err != nil {
		// An unreadable record cannot show an ending.
		log.Printf("secure-agentd: previous run record unreadable: %v", err)
		prev, found = PreviousRun{Ending: RunEndingNoRecord}, true
	}
	t.previous, t.found = prev, found
	return t, t.write()
}

// Previous reports how the run before this one ended, as read at StartRun;
// false when no run was recorded.
func (t *RunTracker) Previous() (PreviousRun, bool) {
	return t.previous, t.found
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
	t.rec.StopIntentAt = at
	return at, at.Add(StopIntentWindow), t.write()
}

// Stop durably writes this run's ending for the stop trigger cause and
// returns it. Only the first call writes; later calls return that ending.
func (t *RunTracker) Stop(cause RunEnding) (RunEnding, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rec.Ending != "" {
		return t.rec.Ending, nil
	}
	at := t.now().UTC()
	ending := cause
	if cause == RunEndingSignal && !t.rec.StopIntentAt.IsZero() && !at.Before(t.rec.StopIntentAt) && at.Sub(t.rec.StopIntentAt) <= StopIntentWindow {
		ending = RunEndingOwnerStop
	}
	t.rec.EndedAt, t.rec.Ending = at, ending
	return ending, t.write()
}

// write persists the record with fsync before rename; callers hold mu or
// have not shared t yet.
func (t *RunTracker) write() error {
	data, err := json.Marshal(t.rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
		return err
	}
	return safefile.WriteFileAtomic(t.path, data, 0o600)
}
