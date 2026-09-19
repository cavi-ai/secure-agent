// Package session resolves every event to a durable session at ingest.
// Resolution is a pipeline, strongest signal first: hook handshake (the
// harness announced itself) > transcript path (harness log naming) >
// process tree (the ancestor-substring heuristic, now the weakest tier).
package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

const (
	// idleAfter: no attributed events for this long flips active → idle.
	idleAfter = 10 * time.Minute
	// endSilentAfter: hook sessions whose root pid never resolved end after
	// a day of silence (no process tree to watch for an exit).
	endSilentAfter = 24 * time.Hour
	// touchThrottle bounds last_seen writes per session.
	touchThrottle = 30 * time.Second
)

// Handshake is the hook's session announcement: harness identity, workspace,
// and the harness's own pid (the hook's parent), which joins the hook
// session id to the process tree exactly.
type Handshake struct {
	SessionID string
	Harness   string
	Workspace string
	Repo      string
	Branch    string
	PID       int32
	TS        time.Time
}

// Resolver attributes events to sessions and maintains their lifecycle.
type Resolver struct {
	st     *store.Store
	tagger *agents.Tagger

	// OnSessionChange, when set, receives the session record after every
	// upsert or lifecycle transition — the session delta published to SSE
	// subscribers so consoles patch instead of refetch.
	OnSessionChange func(model.Session)

	mu     sync.Mutex
	byPID  map[int32]string // pid → session id (process-tree cache)
	byRoot map[int32]string // root pid → session id
	// byScope maps "harness\x00workspace" → provisional process-tree session
	// id, so a transcript sighting joins the running conversation without a
	// store scan. Filled when a process-tree session is created, cleared when
	// it ends.
	byScope map[string]string
	touch   map[string]time.Time // session id → last TouchSession (throttle)
	now     func() time.Time
}

func NewResolver(st *store.Store, tg *agents.Tagger) *Resolver {
	return &Resolver{
		st:      st,
		tagger:  tg,
		byPID:   map[int32]string{},
		byRoot:  map[int32]string{},
		byScope: map[string]string{},
		touch:   map[string]time.Time{},
		now:     time.Now,
	}
}

// scopeKey identifies a harness working directory: the join key between a
// process-tree session and the transcript that names its conversation.
func scopeKey(harness, workspace string) string {
	return harness + "\x00" + workspace
}

// ProcSessionID is the provisional id for a process-tree-resolved session.
// A hook handshake for the same tree rekeys it (hook id wins).
func ProcSessionID(rootPID int32, startedAt time.Time) string {
	return fmt.Sprintf("proc-%d-%d", rootPID, startedAt.UnixNano())
}

// Resolve attributes e to a session, mutating e.SessionID, and maintains the
// session record. Returns "" when nothing can be attributed.
func (r *Resolver) Resolve(e *event.Event) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Tier 1: hook/transcript-stamped id on the event itself.
	if e.SessionID != "" {
		r.ensureHookSession(e)
		r.touchLocked(e.SessionID, e.TS)
		return e.SessionID
	}

	// Tier 3: process tree (the only tier that needs the tagger).
	if e.PID <= 0 {
		return ""
	}
	if id, ok := r.byPID[e.PID]; ok {
		r.touchLocked(id, e.TS)
		return id
	}
	info, ok := r.tagger.Tag(e.PID)
	if !ok {
		return ""
	}
	root := info.RootPID
	if root == 0 {
		root = info.PID
	}
	id, ok := r.byRoot[root]
	if !ok {
		// Adopt a transcript session already known for this harness+workspace
		// (the transcript may have been tailed before the process tree was
		// sampled). Otherwise mint a provisional process-tree id. Either way
		// the scope index points at the current id, so a later transcript
		// sighting merges into it instead of creating a second row.
		if existing, found := r.byScope[scopeKey(info.Name, info.CWD)]; found && info.CWD != "" {
			id = existing
		} else {
			id = ProcSessionID(root, info.StartedAt)
		}
		ts := e.TS
		if ts.IsZero() {
			ts = r.now()
		}
		sess := model.Session{
			ID:            id,
			Harness:       info.Name,
			Workspace:     info.CWD,
			RootPID:       root,
			RootStartedAt: info.StartedAt.UTC().Format(time.RFC3339Nano),
			StartedAt:     ts,
			LastSeenAt:    ts,
			Status:        model.SessionActive,
			Confidence:    model.ConfProcessTree,
		}
		r.st.UpsertSession(sess)
		r.emitLocked(sess)
		r.byRoot[root] = id
		if sess.Workspace != "" {
			r.byScope[scopeKey(sess.Harness, sess.Workspace)] = id
		}
	}
	r.byPID[e.PID] = id
	r.touchLocked(id, e.TS)
	e.SessionID = id
	return id
}

// HandleHandshake registers a hook-announced session. When a process-tree
// session already covers the handshake's pid, it is rekeyed to the hook id —
// the hook's identity is authoritative (workspace, repo, branch included).
func (r *Resolver) HandleHandshake(h Handshake) {
	if h.SessionID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ts := h.TS
	if ts.IsZero() {
		ts = r.now()
	}

	// Join to the process tree: the handshake's pid is the harness process.
	if h.PID > 0 {
		if old, ok := r.byRoot[h.PID]; ok && old != h.SessionID {
			r.st.RekeySession(old, h.SessionID)
			delete(r.byRoot, h.PID)
			for pid, id := range r.byPID {
				if id == old {
					r.byPID[pid] = h.SessionID
				}
			}
		}
		r.byRoot[h.PID] = h.SessionID
		r.byPID[h.PID] = h.SessionID
	}

	r.st.UpsertSession(model.Session{
		ID:         h.SessionID,
		Harness:    h.Harness,
		Workspace:  h.Workspace,
		Repo:       h.Repo,
		Branch:     h.Branch,
		RootPID:    h.PID,
		StartedAt:  ts,
		LastSeenAt: ts,
		Status:     model.SessionActive,
		Confidence: model.ConfHook,
	})
	if sess, ok := r.st.GetSession(h.SessionID); ok {
		r.emitLocked(sess)
	}
	r.touchLocked(h.SessionID, ts)
}

// NoteTranscriptSession records a harness transcript sighting. The id comes
// from the harness's own transcript (e.g. Claude's sessionId), stronger than a
// process-tree guess. `harness` names the source ("claude", "codex", …) and
// `workspace` is the transcript's cwd; both fill the session record so a
// trace session is never nameless.
//
// When a process-tree session already exists for the same harness+workspace
// (the harness process is the one running this conversation), the transcript
// session MERGES INTO it rather than creating a second row — that is the join
// that makes "claude · repo@branch · timeline" possible. The process-tree id
// is provisional; the harness's own id is authoritative, so the merge rekeys
// the process row's events onto the transcript id.
func (r *Resolver) NoteTranscriptSession(id, harness, workspace string, ts time.Time) {
	if id == "" {
		return
	}
	if ts.IsZero() {
		ts = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Join: if a process-tree session covers this harness+workspace and is
	// still provisional, rekey it to the harness id so its events follow.
	if workspace != "" && harness != "" {
		if old, ok := r.findProvisionalLocked(harness, workspace); ok && old != id {
			r.st.RekeySession(old, id)
			for pid, sid := range r.byPID {
				if sid == old {
					r.byPID[pid] = id
				}
			}
			for root, sid := range r.byRoot {
				if sid == old {
					r.byRoot[root] = id
				}
			}
		}
		// Keep the scope index pointing at the current id so a process-tree
		// session created after this sighting adopts the conversation.
		r.byScope[scopeKey(harness, workspace)] = id
	}

	r.st.UpsertSession(model.Session{
		ID: id, Harness: harness, Workspace: workspace,
		StartedAt: ts, LastSeenAt: ts,
		Status: model.SessionActive, Confidence: model.ConfTranscript,
	})
	if stored, ok := r.st.GetSession(id); ok {
		r.emitLocked(stored)
	}
	r.touchLocked(id, ts)
}

// findProvisionalLocked returns the process-tree session id for a
// harness+workspace whose conversation id is not yet known. Caller holds mu.
func (r *Resolver) findProvisionalLocked(harness, workspace string) (string, bool) {
	id, ok := r.byScope[scopeKey(harness, workspace)]
	return id, ok
}

// ensureHookSession creates a minimal record for a hook-stamped id seen
// without a handshake (e.g. activity log lines predating registration).
func (r *Resolver) ensureHookSession(e *event.Event) {
	ts := e.TS
	if ts.IsZero() {
		ts = r.now()
	}
	sess := model.Session{
		ID:         e.SessionID,
		StartedAt:  ts,
		LastSeenAt: ts,
		Status:     model.SessionActive,
		Confidence: model.ConfHook,
	}
	if e.PID > 0 {
		if info, ok := r.tagger.Tag(e.PID); ok {
			sess.Harness = info.Name
			if sess.Workspace == "" {
				sess.Workspace = info.CWD
			}
		}
	}
	r.st.UpsertSession(sess)
	if stored, ok := r.st.GetSession(e.SessionID); ok {
		r.emitLocked(stored)
	}
}

// emitLocked notifies delta subscribers of a session change (nil-safe).
func (r *Resolver) emitLocked(sess model.Session) {
	if r.OnSessionChange != nil {
		r.OnSessionChange(sess)
	}
}

// touchLocked bumps last_seen at most once per touchThrottle per session.
func (r *Resolver) touchLocked(id string, ts time.Time) {
	if ts.IsZero() {
		ts = r.now()
	}
	if last, ok := r.touch[id]; ok && ts.Sub(last) < touchThrottle {
		return
	}
	r.touch[id] = ts
	r.st.TouchSession(id, ts)
}

// WorkspaceFor returns the workspace recorded for a session id ("" if none) —
// so flags/incidents can carry the workspace that per-workspace notification
// scopes key on without a second resolution pass.
func (r *Resolver) WorkspaceFor(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	if sess, ok := r.st.GetSession(sessionID); ok {
		return sess.Workspace
	}
	return ""
}

// Sweep advances the lifecycle: active → idle after silence, idle → ended
// when the root process is gone (or after a day of silence for pid-less
// hook sessions). Call on the tagger refresh cadence.
func (r *Resolver) Sweep() {
	now := r.now()
	idled := r.st.MarkSessionsIdle(now.Add(-idleAfter))

	live := map[int32]bool{}
	for pid := range r.tagger.TaggedPIDs() {
		live[pid] = true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for root, id := range r.byRoot {
		if !live[root] {
			r.st.EndSession(id, now)
			if sess, ok := r.st.GetSession(id); ok {
				r.emitLocked(sess)
			}
			delete(r.byRoot, root)
			for pid, sid := range r.byPID {
				if sid == id {
					delete(r.byPID, pid)
				}
			}
			for scope, sid := range r.byScope {
				if sid == id {
					delete(r.byScope, scope)
				}
			}
		}
	}
	// Sessions known to the store but not to the in-memory maps (daemon
	// restarted mid-session): end those whose root pid is not live, and end
	// pid-less hook sessions after a day of silence.
	for root, id := range r.st.SessionRoots() {
		if _, tracked := r.byRoot[root]; !tracked && !live[root] {
			r.st.EndSession(id, now)
			if sess, ok := r.st.GetSession(id); ok {
				r.emitLocked(sess)
			}
		}
	}
	for _, sess := range r.st.ListSessions(store.SessionFilter{Status: model.SessionIdle, Limit: 500}) {
		if sess.RootPID == 0 && now.Sub(sess.LastSeenAt) > endSilentAfter {
			r.st.EndSession(sess.ID, now)
			if stored, ok := r.st.GetSession(sess.ID); ok {
				r.emitLocked(stored)
			}
		}
	}
	// Idle transitions ride the delta stream too (the console's status chip
	// must move without a poll).
	for _, id := range idled {
		if sess, ok := r.st.GetSession(id); ok {
			r.emitLocked(sess)
		}
	}
}
