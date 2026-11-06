package daemon

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// repeatActivityWindow is how long, at least, a repeat of stored file or exec
// activity folds into its stored row.
const repeatActivityWindow = time.Minute

// activityKey is what a repeat adds nothing to: within a session, one file
// opened, or one executable started by the same image; without a session,
// one process's open or exec.
type activityKey struct {
	kind    event.Kind
	session string
	pid     int32 // only without a session
	exe     string
	path    string
}

// activityKeyOf reports e's key when its repeats fold: file opens and execs.
func activityKeyOf(e event.Event) (activityKey, bool) {
	if (e.Kind != event.KindFileOpen && e.Kind != event.KindExec) || e.Path == "" {
		return activityKey{}, false
	}
	k := activityKey{kind: e.Kind, session: e.SessionID, path: e.Path}
	if k.session == "" {
		k.pid = e.PID
	}
	if e.Kind == event.KindExec {
		k.exe = e.ExePath
	}
	return k, true
}

// repeatActivity remembers, by event time, the activity stored in the current
// and the previous window. Memory is bounded by two windows of distinct keys.
type repeatActivity struct {
	window            time.Duration
	start             time.Time
	current, previous map[activityKey]struct{}
}

// seen reports whether activity with e's key was stored within the window.
func (r *repeatActivity) seen(e event.Event) bool {
	k, ok := activityKeyOf(e)
	if !ok {
		return false
	}
	switch since := e.TS.Sub(r.start); {
	case r.current == nil || since >= 2*r.window:
		r.previous, r.current, r.start = nil, map[activityKey]struct{}{}, e.TS
	case since >= r.window:
		r.previous, r.current, r.start = r.current, map[activityKey]struct{}{}, e.TS
	}
	if _, ok := r.current[k]; ok {
		return true
	}
	_, ok = r.previous[k]
	return ok
}

// remember records stored activity.
func (r *repeatActivity) remember(e event.Event) {
	k, ok := activityKeyOf(e)
	if !ok || r.current == nil {
		return
	}
	r.current[k] = struct{}{}
}
