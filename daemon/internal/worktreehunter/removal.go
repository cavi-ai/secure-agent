package worktreehunter

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

// Removal states, phases (in the order a removal passes them) and the
// step text of each phase.
const (
	RemovalRunning = "running"
	RemovalRemoved = "removed"
	RemovalFailed  = "failed"

	PhaseWaiting   = "waiting"
	PhaseChecking  = "checking"
	PhaseMeasuring = "measuring"
	PhaseDeleting  = "deleting"

	StepWaiting   = "waiting for the current scan"
	StepChecking  = "checking it is still safe to remove"
	StepMeasuring = "measuring"
	StepDeleting  = "deleting"
)

var stepText = map[string]string{
	PhaseWaiting: StepWaiting, PhaseChecking: StepChecking,
	PhaseMeasuring: StepMeasuring, PhaseDeleting: StepDeleting,
}

// removalTTL is how long a finished removal stays listed.
const removalTTL = 30 * time.Minute

// ErrRemoving refuses a second removal of a worktree while one runs.
var ErrRemoving = errors.New("a removal of this worktree is already running")

// Removal is one removal's progress and outcome. While it runs, Phase and
// Step name what it does and StepAt when that began; Bytes and Files are
// known from the measuring phase on.
type Removal struct {
	Path       string     `json:"path"`
	State      string     `json:"state"`
	Phase      string     `json:"phase,omitempty"`
	Step       string     `json:"step,omitempty"`
	StepAt     *time.Time `json:"step_at,omitempty"`
	Error      string     `json:"error,omitempty"`
	RowState   string     `json:"row_state,omitempty"` // the fresh verdict when it was not removable
	Reasons    []string   `json:"reasons,omitempty"`
	Branch     string     `json:"branch,omitempty"`
	Bytes      int64      `json:"bytes,omitempty"`
	Files      int        `json:"files,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// removalProgress receives a removal's phases and the measured size of
// the tree it is about to delete.
type removalProgress interface {
	phase(p string)
	measured(bytes int64, files int)
}

type removalJob struct {
	h    *Hunter
	path string
}

// beginRemoval registers a running removal of path.
func (h *Hunter) beginRemoval(path string) (removalJob, error) {
	path = filepath.Clean(path)
	h.remMu.Lock()
	defer h.remMu.Unlock()
	if r, ok := h.removals[path]; ok && r.State == RemovalRunning {
		return removalJob{}, ErrRemoving
	}
	h.removals[path] = &Removal{Path: path, State: RemovalRunning, StartedAt: h.now().UTC()}
	return removalJob{h: h, path: path}, nil
}

func (j removalJob) phase(p string) {
	j.h.remMu.Lock()
	defer j.h.remMu.Unlock()
	if r := j.h.removals[j.path]; r != nil {
		at := j.h.now().UTC()
		r.Phase, r.Step, r.StepAt = p, stepText[p], &at
	}
}

func (j removalJob) measured(bytes int64, files int) {
	j.h.remMu.Lock()
	defer j.h.remMu.Unlock()
	if r := j.h.removals[j.path]; r != nil {
		r.Bytes, r.Files = bytes, files
	}
}

func (j removalJob) finish(row Worktree, err error) {
	j.h.remMu.Lock()
	defer j.h.remMu.Unlock()
	r := j.h.removals[j.path]
	if r == nil {
		return
	}
	at := j.h.now().UTC()
	r.FinishedAt, r.Phase, r.Step, r.StepAt, r.Branch, r.Bytes = &at, "", "", nil, row.Branch, row.SizeBytes
	var refused *NotRemovableError
	switch {
	case err == nil:
		r.State = RemovalRemoved
	case errors.As(err, &refused):
		r.State, r.Error, r.RowState, r.Reasons = RemovalFailed, "not removed: it is now "+refused.Row.State, refused.Row.State, refused.Row.Reasons
	default:
		r.State, r.Error = RemovalFailed, err.Error()
	}
}

// StartRemove removes path in the background and returns the running
// removal; Removals reports its steps and outcome.
func (h *Hunter) StartRemove(path string) (Removal, error) {
	if !filepath.IsAbs(path) {
		return Removal{}, errors.New("path must be absolute")
	}
	job, err := h.beginRemoval(path)
	if err != nil {
		return Removal{}, err
	}
	h.remWG.Add(1)
	go func() {
		defer h.remWG.Done()
		row, err := h.remove(context.Background(), path, job)
		job.finish(row, err)
	}()
	return h.removal(job.path), nil
}

func (h *Hunter) removal(path string) Removal {
	h.remMu.Lock()
	defer h.remMu.Unlock()
	if r := h.removals[path]; r != nil {
		return *r
	}
	return Removal{}
}

// Removals returns running removals and those that ended within
// removalTTL, by path.
func (h *Hunter) Removals() map[string]Removal {
	h.remMu.Lock()
	defer h.remMu.Unlock()
	now := h.now()
	out := map[string]Removal{}
	for p, r := range h.removals {
		if r.FinishedAt != nil && now.Sub(*r.FinishedAt) > removalTTL {
			delete(h.removals, p)
			continue
		}
		out[p] = *r
	}
	return out
}
