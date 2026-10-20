package daemon

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// repeatOpenWindow is how long, at least, a process's further opens of a file
// fold into its stored open of that file.
const repeatOpenWindow = time.Minute

type openKey struct {
	pid  int32
	path string
}

// repeatOpens remembers, by event time, the file opens stored in the current
// and the previous window. Memory is bounded by two windows of distinct opens.
type repeatOpens struct {
	window            time.Duration
	start             time.Time
	current, previous map[openKey]struct{}
}

// seen reports whether e's process had an open of e's file stored within the
// window.
func (r *repeatOpens) seen(e event.Event) bool {
	if e.Kind != event.KindFileOpen || e.Path == "" {
		return false
	}
	switch since := e.TS.Sub(r.start); {
	case r.current == nil || since >= 2*r.window:
		r.previous, r.current, r.start = nil, map[openKey]struct{}{}, e.TS
	case since >= r.window:
		r.previous, r.current, r.start = r.current, map[openKey]struct{}{}, e.TS
	}
	k := openKey{e.PID, e.Path}
	if _, ok := r.current[k]; ok {
		return true
	}
	_, ok := r.previous[k]
	return ok
}

// remember records a stored open.
func (r *repeatOpens) remember(e event.Event) {
	if e.Kind != event.KindFileOpen || e.Path == "" || r.current == nil {
		return
	}
	r.current[openKey{e.PID, e.Path}] = struct{}{}
}
