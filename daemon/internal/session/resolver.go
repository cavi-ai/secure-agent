// Package session resolves every event to a durable session at ingest.
// Resolution is a pipeline, strongest signal first: hook handshake (the
// harness announced itself) > transcript path (harness log naming) >
// process tree (the ancestor-substring heuristic, now the weakest tier).
package session

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
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
	// endInfraRootAfter: a session whose root pid now belongs to an infra
	// family other than its own harness ends after this much silence.
	endInfraRootAfter = time.Hour
	// touchThrottle bounds last_seen writes per session.
	touchThrottle = 30 * time.Second
	// minSessionLifetime is how long a process-tree session must stay live
	// before it is persisted: orchestrated bounded-turn runs mint one
	// throwaway codex root every few seconds; sub-minute trees get
	// attributed in memory but never become rows. No workspace-path rule:
	// any path marker also matches long-lived conversations under that path.
	minSessionLifetime = 60 * time.Second
)

// gitCacheTTL bounds how long a workspace's repo resolution is trusted:
// workspaces move between repos (a scratch dir becomes a checkout, a
// worktree is removed) and a process-lifetime memo served stale values.
const gitCacheTTL = 10 * time.Minute

type gitInfo struct {
	repo, branch string
	at           time.Time
}

// GitInfoFor reads repo and branch from the workspace's ENCLOSING git root —
// workspaces are often subdirectories of a checkout, and the repo is the
// root's basename, not the workspace's. A path with no enclosing .git yields
// empty strings ("" is honest; the basename of a non-repo is noise like "/"
// or ".config"). Results memoize per workspace for gitCacheTTL. Call sites
// hold the resolver mutex, so the map needs no lock of its own. Exported for
// the store's repair pass over rows written by older resolvers.
func GitInfoFor(workspace string) (repo, branch string) {
	// A workspace label that is not an absolute path ("openclaw:<agent>")
	// has no checkout; walking it would resolve the daemon's own cwd.
	if workspace == "" || !filepath.IsAbs(workspace) {
		return "", ""
	}
	if gitCache == nil {
		gitCache = map[string]gitInfo{}
	}
	if v, ok := gitCache[workspace]; ok && time.Since(v.at) < gitCacheTTL {
		return v.repo, v.branch
	}
	repo, branch = resolveGitInfo(workspace)
	gitCache[workspace] = gitInfo{repo: repo, branch: branch, at: time.Now()}
	return repo, branch
}

// IsGitWorkspace checks eligibility for repo-attribution diagnostics without
// touching the resolver's cache, which is protected by its own mutex.
func IsGitWorkspace(workspace string) bool {
	if !filepath.IsAbs(workspace) {
		return false
	}
	repo, _ := resolveGitInfo(workspace)
	return repo != ""
}

// resolveGitInfo walks up from workspace looking for a .git entry (directory
// or worktree link file), the same rule git itself applies.
func resolveGitInfo(workspace string) (repo, branch string) {
	dir := filepath.Clean(workspace)
	for {
		// Detached worktrees and submodule checkouts carry the real git dir
		// in the .git FILE ("gitdir: ..."); a normal checkout is a directory.
		gitDir := filepath.Join(dir, ".git")
		st, err := os.Stat(gitDir)
		if err == nil {
			if !st.IsDir() {
				if data, rerr := os.ReadFile(gitDir); rerr == nil {
					line := strings.TrimSpace(string(data))
					if rest, ok := strings.CutPrefix(line, "gitdir:"); ok {
						gitDir = strings.TrimSpace(rest)
						if !filepath.IsAbs(gitDir) {
							gitDir = filepath.Join(dir, gitDir)
						}
					}
				}
			}
			repo = filepath.Base(dir)
			if head, herr := os.ReadFile(filepath.Join(gitDir, "HEAD")); herr == nil {
				line := strings.TrimSpace(string(head))
				if ref, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
					branch = strings.TrimSpace(ref)
				}
			}
			return repo, branch
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ""
		}
		dir = parent
	}
}

var gitCache map[string]gitInfo

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
	st     resolverStore
	tagger *agents.Tagger

	// OnSessionChange, when set, receives the session record after every
	// upsert or lifecycle transition — the session delta published to SSE
	// subscribers so consoles patch instead of refetch.
	OnSessionChange func(model.Session)

	mu     sync.Mutex
	byPID  map[int32]string // pid → session id (process-tree cache)
	byRoot map[int32]string // root pid → session id
	// byScope maps "harness\x00workspace" → the scope's newest session id,
	// so a transcript sighting joins the running conversation without a
	// store scan. Filled when a process-tree session is created, cleared when
	// it ends. A join through it needs a family-root match
	// (adoptsByScopeLocked, findProvisionalLocked): two processes in one
	// working directory never share a session.
	byScope map[string]string
	touch   map[string]time.Time // session id → last TouchSession (throttle)
	// deferred holds process-tree sessions awaiting the lifetime floor or a
	// successful write: attributed in memory, not yet persisted. touchLocked
	// saves eligible sessions and retains them on failure; Sweep drops dead
	// roots so a bounded-turn flood never touches the disk.
	deferred map[string]model.Session
	// sighted is each session's last transcript or hook sighting by wall
	// clock: a conversation read or a hook fired, not a process touching
	// files. Doctor's trace coverage counts these (SightedByHarness).
	sighted map[string]sighting
	now     func() time.Time
}

type sighting struct {
	harness string
	at      time.Time
}

// maxSightings bounds the sighting map; past it, sightings older than a day
// are dropped.
const maxSightings = 10000

// resolverStore keeps identity reads and lifecycle writes explicit. A missing
// session permits attribution; an unavailable read must not reassign ownership.
type resolverStore interface {
	GetSession(string) (model.Session, bool, error)
	ListSessions(store.SessionFilter) ([]model.Session, error)
	UpsertSession(model.Session) error
	PromoteSession(model.Session, string) error
	RekeySession(string, string) error
	TouchSession(string, time.Time) error
	MarkSessionsIdle(time.Time) ([]string, error)
	SessionRoots() map[int32][]model.Session
	EndSession(string, time.Time) error
	ResumeSession(string, time.Time) (bool, error)
}

func NewResolver(st resolverStore, tg *agents.Tagger) *Resolver {
	return &Resolver{
		st:       st,
		tagger:   tg,
		byPID:    map[int32]string{},
		byRoot:   map[int32]string{},
		byScope:  map[string]string{},
		touch:    map[string]time.Time{},
		deferred: map[string]model.Session{},
		sighted:  map[string]sighting{},
		now:      time.Now,
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
		if r.ensureHookSession(e) {
			r.resumeLocked(e)
			r.touchLocked(e.SessionID, e.TS)
		}
		if !isTraceKind(e.Kind) {
			r.noteSightingLocked(e.SessionID, "") // hook activity
		}
		return e.SessionID
	}

	// Tier 3: process tree (the only tier that needs the tagger).
	if e.PID <= 0 {
		return ""
	}
	if id, ok := r.byPID[e.PID]; ok {
		r.touchLocked(id, e.TS)
		e.SessionID = id
		return id
	}
	pid := e.PID
	info, ok := r.tagger.Tag(pid)
	if !ok {
		// A short-lived child (git, a shell) has often exited before its ES
		// event is resolved, so the process table no longer holds it. ES
		// recorded its parent at event time: the event is the parent's
		// family's. The child's pid is not cached; it is gone and its number
		// will be reused.
		if e.PPID <= 1 || e.PPID == e.PID {
			return ""
		}
		pid = e.PPID
		if id, ok := r.byPID[pid]; ok {
			r.touchLocked(id, e.TS)
			e.SessionID = id
			return id
		}
		if info, ok = r.tagger.Tag(pid); !ok {
			return ""
		}
	}
	root := info.RootPID
	if root == 0 {
		root = info.PID
	}
	id, ok := r.byRoot[root]
	if !ok {
		// The session is the family root's: a child process (a shell the
		// harness spawned) must not lend it its own start time or cwd.
		if root != info.PID {
			if rootInfo, tagged := r.tagger.Tag(root); tagged {
				info = rootInfo
			}
		}
		// Adopt a transcript session already known for this harness+workspace
		// (the transcript may have been tailed before the process tree was
		// sampled) when it has no root yet or is on this root. Otherwise mint
		// a provisional process-tree id. Either way the scope index points at
		// the current id, so a later transcript sighting merges into it
		// instead of creating a second row.
		if existing, found := r.byScope[scopeKey(info.Name, info.CWD)]; found && info.CWD != "" && r.adoptsByScopeLocked(existing, root, info.Name, info.CWD) {
			id = existing
		} else {
			id = ProcSessionID(root, info.StartedAt)
		}
		ts := e.TS
		if ts.IsZero() {
			ts = r.now()
		}
		// For a process discovered days after it launched, discovery time is
		// not the session start — stamping every boot's registration burst
		// "created now" makes restarts look like session floods. Process
		// start is the session start for a CLI harness (the id already
		// embeds it); fall back to discovery time only when start is unknown.
		startedAt := info.StartedAt
		if startedAt.IsZero() {
			startedAt = ts
		}
		repo, branch := GitInfoFor(info.CWD)
		sess := model.Session{
			ID:            id,
			Harness:       info.Name,
			Workspace:     info.CWD,
			Repo:          repo,
			Branch:        branch,
			RootPID:       root,
			RootStartedAt: info.StartedAt.UTC().Format(time.RFC3339Nano),
			StartedAt:     startedAt,
			LastSeenAt:    ts,
			Status:        model.SessionActive,
			Confidence:    model.ConfProcessTree,
		}
		// Orchestrated bounded-turn runs: the codex root's parent chain
		// reaches a DIFFERENT tagged family (the orchestrator process). Nest
		// this session under that family's session as a child so one run
		// reads as one parent, not hundreds of stubs.
		sess.ParentID = r.orchestratorForLocked(root, info.Name)
		// Use the same persistence path for initial creation and promotion.
		// touchLocked applies the lifetime floor, publishes saved identity,
		// and retains this record for the next activity if the write fails.
		r.deferred[id] = sess
		// A recent transcript touch must not throttle this root attachment.
		delete(r.touch, id)
		r.byRoot[root] = id
		if sess.Workspace != "" {
			r.byScope[scopeKey(sess.Harness, sess.Workspace)] = id
		}
	}
	r.byPID[pid] = id
	r.touchLocked(id, e.TS)
	e.SessionID = id
	return id
}

// adoptsByScopeLocked reports whether family root may adopt the scope's
// session id: one already on this root, or one with no root yet while no
// other family root holds a session in the scope. A second process in the
// same working directory mints its own session; a stored process-tree row's
// root is never overwritten, and the refusal is logged (once per session and
// root: byRoot then holds the minted id). Caller holds mu.
func (r *Resolver) adoptsByScopeLocked(id string, root int32, harness, workspace string) bool {
	sess, ok, err := r.lookupLocked(id)
	if err != nil {
		return false
	}
	if !ok || sess.RootPID == 0 {
		return !r.otherRootInScopeLocked(harness, workspace, root)
	}
	if sess.RootPID == root {
		return true
	}
	if _, deferred := r.deferred[id]; !deferred && sess.Confidence == model.ConfProcessTree {
		log.Printf("session: %s keeps root %d; root %d in the same %s workspace gets its own session", id, sess.RootPID, root, harness)
	}
	return false
}

// otherRootInScopeLocked reports whether a family root other than root holds
// a session in the harness+workspace scope. Caller holds mu.
func (r *Resolver) otherRootInScopeLocked(harness, workspace string, root int32) bool {
	for other := range r.byRoot {
		if other == root {
			continue
		}
		if info, ok := r.tagger.Tag(other); ok && info.Name == harness && info.CWD == workspace {
			return true
		}
	}
	return false
}

// lookupLocked returns session id from the deferred set, then the store.
// Caller holds mu.
func (r *Resolver) lookupLocked(id string) (model.Session, bool, error) {
	if sess, ok := r.deferred[id]; ok {
		return sess, true, nil
	}
	return r.st.GetSession(id)
}

// maxAncestry bounds the OS ancestry walk from a session root.
const maxAncestry = 32

// orchestratorForLocked returns the session id of the tagged family whose
// process spawned this root — the parent for orchestrated children. It walks
// the OS ancestry (the tag chain stops at the root's own harness match, so it
// never reaches the orchestrator): untagged, infra and same-harness ancestors
// are skipped, the nearest ancestor of another agent harness names the
// orchestrator family, and that family's session is the one held by its
// highest contiguous ancestor. "" when the ancestry holds no other agent
// harness or its family has no session yet.
func (r *Resolver) orchestratorForLocked(root int32, harness string) string {
	var family string
	var run []int32
	seen := map[int32]bool{root: true}
	for pid, hops := root, 0; hops < maxAncestry; hops++ {
		ppid, ok := r.tagger.ParentPID(pid)
		if !ok || ppid <= 1 || seen[ppid] {
			break
		}
		seen[ppid] = true
		pid = ppid
		info, tagged := r.tagger.Tag(pid)
		if family == "" {
			if !tagged || info.Kind == config.AgentKindInfra || info.Name == harness {
				continue
			}
			family = info.Name
		} else if !tagged || info.Name != family {
			break
		}
		run = append(run, pid)
	}
	for i := len(run) - 1; i >= 0; i-- {
		if sid, ok := r.byRoot[run[i]]; ok {
			return sid
		}
	}
	return ""
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
	r.noteSightingLocked(h.SessionID, h.Harness)

	ts := h.TS
	if ts.IsZero() {
		ts = r.now()
	}

	// Join to the process tree: the handshake's pid is the harness process.
	if h.PID > 0 {
		if old, ok := r.byRoot[h.PID]; ok && old != h.SessionID {
			if !r.rekeyLocked(old, h.SessionID) {
				return
			}
		}
		r.byRoot[h.PID] = h.SessionID
		r.byPID[h.PID] = h.SessionID
	}

	if !r.upsertAndEmitLocked(model.Session{
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
	}) {
		return
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
	r.NoteTranscriptSighting(TranscriptSighting{ID: id, Harness: harness, Workspace: workspace, TS: ts})
}

// TranscriptSighting is a harness's own record of a conversation. Repo and
// Branch, when the harness records them (Hermes's git_repo_root and
// git_branch), win over the workspace probe; ParentID nests a continuation or
// subagent conversation under the one that spawned it.
type TranscriptSighting struct {
	ID, Harness, Workspace string
	Repo, Branch, ParentID string
	// Origin names who spawned the conversation (model.Session.Origin).
	Origin string
	TS     time.Time
}

// NoteTranscriptSighting is NoteTranscriptSession with the harness's own
// repo, branch, parent and origin.
func (r *Resolver) NoteTranscriptSighting(s TranscriptSighting) {
	id, harness, workspace, ts := s.ID, s.Harness, s.Workspace, s.TS
	if id == "" {
		return
	}
	if ts.IsZero() {
		ts = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.noteSightingLocked(id, harness)

	// Join: rekey only a process-tree session — the harness's own transcript
	// id is authoritative over a provisional one. A second transcript id in
	// the same workspace is a sibling conversation, not a rename.
	if workspace != "" && harness != "" {
		old, ok, err := r.findProvisionalLocked(id, harness, workspace)
		if err != nil {
			return
		}
		if ok {
			if !r.rekeyLocked(old, id) {
				return
			}
		}
		// Keep the scope index pointing at the current id so a process-tree
		// session created after this sighting adopts the conversation.
		r.byScope[scopeKey(harness, workspace)] = id
	}

	repo, branch := s.Repo, s.Branch
	if repo == "" {
		repo, branch = GitInfoFor(workspace)
	}
	if !r.upsertAndEmitLocked(model.Session{
		ID: id, Harness: harness, Workspace: workspace,
		Repo: repo, Branch: branch, ParentID: s.ParentID, Origin: s.Origin,
		StartedAt: ts, LastSeenAt: ts,
		Status: model.SessionActive, Confidence: model.ConfTranscript,
	}) {
		return
	}
	r.touchLocked(id, ts)
}

// EndTranscriptSession ends a conversation the harness's own state reports
// finished (openclaw's lcm.db marks it inactive or archived). Pid-less
// transcript sessions have no process exit to watch.
func (r *Resolver) EndTranscriptSession(id string, ts time.Time) {
	if id == "" {
		return
	}
	if ts.IsZero() {
		ts = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endLocked(id, ts)
}

// rekeyLocked moves session old onto the authoritative id: the stored row,
// its events and flags follow (RekeySession), a deferred session is promoted
// under the new id unconditionally (a named conversation is not a scratch
// run; the floor applies to nameless ones), and every in-memory index that
// held old points at id. A scope entry for old is dropped rather than moved,
// so a new process in that scope mints its own session instead of adopting
// this conversation. Caller holds mu.
func (r *Resolver) rekeyLocked(old, id string) bool {
	var err error
	if sess, ok := r.deferred[old]; ok {
		err = r.st.PromoteSession(sess, id)
	} else {
		err = r.st.RekeySession(old, id)
	}
	if err != nil {
		log.Printf("session: rekey failed: %v", err)
		return false
	}
	delete(r.deferred, old)
	delete(r.touch, old)
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
	for scope, sid := range r.byScope {
		if sid == old {
			delete(r.byScope, scope)
		}
	}
	return true
}

// findProvisionalLocked returns the process-tree session transcript session
// id merges into: the scope's newest session, when it is a process-tree row on
// the transcript's family root (the root JoinTranscriptPID recorded) or, before
// the transcript has a root, when no other family root holds a session in the
// scope. A sighting cannot tell which of two processes in one working
// directory holds the transcript; JoinTranscriptPID settles it. Caller holds
// mu.
func (r *Resolver) findProvisionalLocked(id, harness, workspace string) (string, bool, error) {
	old, ok := r.byScope[scopeKey(harness, workspace)]
	if !ok || old == id {
		return "", false, nil
	}
	cand, ok, err := r.lookupLocked(old)
	if err != nil {
		return "", false, err
	}
	if !ok || cand.Confidence != model.ConfProcessTree {
		return "", false, nil
	}
	t, ok, err := r.st.GetSession(id)
	if err != nil {
		return "", false, err
	}
	if ok && t.RootPID != 0 {
		if t.RootPID != cand.RootPID {
			return "", false, nil
		}
		return old, true, nil
	}
	if r.otherRootInScopeLocked(harness, workspace, cand.RootPID) {
		return "", false, nil
	}
	return old, true, nil
}

// confidenceLocked reports the confidence tier of a session id: deferred
// (in-memory) sessions first, then the store. Caller holds mu.
func (r *Resolver) confidenceLocked(id string) (string, error) {
	sess, ok, err := r.lookupLocked(id)
	if err != nil {
		return "", err
	}
	if ok {
		return sess.Confidence, nil
	}
	return "", nil
}

// ensureHookSession creates a minimal record for a stamped id seen without a
// handshake (e.g. activity log lines predating registration). A trace record
// (tool, turn or model call) comes from the harness's own transcript or
// state database, so it names a transcript session; hook-origin events name
// a hook session. A stamped event from a tagged pid joins its process tree.
func (r *Resolver) ensureHookSession(e *event.Event) bool {
	ts := e.TS
	if ts.IsZero() {
		ts = r.now()
	}
	conf := model.ConfHook
	if isTraceKind(e.Kind) {
		conf = model.ConfTranscript
	}
	sess := model.Session{
		ID:         e.SessionID,
		StartedAt:  ts,
		LastSeenAt: ts,
		Status:     model.SessionActive,
		Confidence: conf,
	}
	if e.PID > 0 {
		if info, ok := r.tagger.Tag(e.PID); ok {
			sess.Harness = info.Name
			if sess.Workspace == "" {
				sess.Workspace = info.CWD
			}
			if !r.joinTreeLocked(&sess, e.PID, info) {
				return false
			}
		}
	}
	if sess.Repo == "" {
		sess.Repo, sess.Branch = GitInfoFor(sess.Workspace)
	}
	return r.upsertAndEmitLocked(sess)
}

// resumeLocked reopens an ended session on the harness's own record of work
// (a tool call, turn, model call or hook action) dated by the record after
// the end. A root that no longer runs the recorded process keeps it ended
// until the process holding the conversation joins. Caller holds mu, after
// the session upsert.
func (r *Resolver) resumeLocked(e *event.Event) {
	if e.ObservedTS || (!isTraceKind(e.Kind) && e.Kind != event.KindPluginAction) {
		return
	}
	sess, ok, err := r.st.GetSession(e.SessionID)
	if err != nil || !ok || sess.Status != model.SessionEnded || !r.rootLive(sess) {
		return
	}
	resumed, err := r.st.ResumeSession(sess.ID, e.TS)
	if err != nil {
		log.Printf("session: persist resume: %v", err)
		return
	}
	if !resumed {
		return
	}
	r.holdRootLocked(sess)
	if saved, ok, err := r.st.GetSession(sess.ID); err == nil && ok {
		r.emitLocked(saved)
	}
}

// rootLive reports whether the session's root still runs the process it
// recorded (the same start time, when recorded). A session without a root
// counts as live.
func (r *Resolver) rootLive(sess model.Session) bool {
	return sess.RootPID == 0 || !r.rootGone(sess.RootPID, rootStarted(sess))
}

// rootGone reports whether root no longer runs the process a session
// recorded: the pid is gone, or a process started at another time holds it.
// A zero recorded start checks the pid alone.
func (r *Resolver) rootGone(root int32, recorded time.Time) bool {
	started, ok := r.tagger.Started(root)
	if !ok {
		return true
	}
	return !recorded.IsZero() && !started.IsZero() && !started.Equal(recorded)
}

// holdRootLocked gives a resumed session back the root endLocked released: a
// free root is taken, a process-tree session holding it merges in, and a
// sibling conversation holding it keeps it. Caller holds mu.
func (r *Resolver) holdRootLocked(sess model.Session) {
	root := sess.RootPID
	if root == 0 {
		return
	}
	if old, held := r.byRoot[root]; held && old != sess.ID {
		confidence, err := r.confidenceLocked(old)
		if err != nil || confidence != model.ConfProcessTree || !r.rekeyLocked(old, sess.ID) {
			return
		}
	}
	r.byRoot[root] = sess.ID
	r.byPID[root] = sess.ID
}

// joinTreeLocked ties a stamped session to the process tree its event came
// from, as HandleHandshake does for a handshake pid: the family root becomes
// the session's root (Sweep ends it when the root exits; the tree's unstamped
// events resolve to it), and a provisional process-tree session holding that
// root is rekeyed into it. A root already held by another hook or transcript
// session is a sibling conversation in the same process — never merged; the
// newest conversation takes the root. Runs on every stamped event, so an
// event that raced the tagger at process start joins on the next one.
// Caller holds mu, before the session upsert.
func (r *Resolver) joinTreeLocked(sess *model.Session, pid int32, info agents.AgentInfo) bool {
	root := info.RootPID
	if root == 0 {
		root = info.PID
	}
	rootInfo := info
	if root != info.PID {
		if ri, ok := r.tagger.Tag(root); ok {
			rootInfo = ri
		}
	}
	sess.RootPID = root
	if !rootInfo.StartedAt.IsZero() {
		sess.RootStartedAt = rootInfo.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	old, held := r.byRoot[root]
	if held && old == sess.ID {
		r.byPID[pid] = sess.ID
		return true
	}
	var confidence string
	if held {
		var err error
		confidence, err = r.confidenceLocked(old)
		if err != nil {
			return false
		}
	}
	if held && confidence == model.ConfProcessTree {
		// The rekeyed row carries its orchestrator parent with it.
		if !r.rekeyLocked(old, sess.ID) {
			return false
		}
	} else {
		// No process-tree row to inherit from: nest under the orchestrator
		// as the process-tree session would have.
		sess.ParentID = r.orchestratorForLocked(root, info.Name)
	}
	r.byRoot[root] = sess.ID
	r.byPID[pid] = sess.ID
	return true
}

// JoinTranscriptPID ties a transcript session to the process that holds its
// transcript open (a codex process appending to its rollout) — the join the
// harness+workspace key misses when an orchestrated process runs in another
// cwd. As joinTreeLocked: the tagged family root becomes the session's root,
// a process-tree row holding that root is rekeyed into the session, and the
// session nests under the orchestrator otherwise. The newest conversation
// holds the root: a session started before the transcript session already
// holding it records the root on its row but does not take it. Repeat calls
// are no-ops; untagged pids and unknown sessions are ignored.
func (r *Resolver) JoinTranscriptPID(id string, pid int32) {
	if id == "" || pid <= 0 {
		return
	}
	info, ok := r.tagger.Tag(pid)
	if !ok {
		return
	}
	root := info.RootPID
	if root == 0 {
		root = info.PID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok, err := r.st.GetSession(id)
	if err != nil || !ok {
		return
	}
	old, held := r.byRoot[root]
	if held && old == id && sess.RootPID == root {
		r.byPID[pid] = id
		return
	}
	if held && old != id {
		confidence, err := r.confidenceLocked(old)
		if err != nil {
			return
		}
		newer, ok, err := r.st.GetSession(old)
		if err != nil {
			return
		}
		if confidence != model.ConfProcessTree && ok && newer.StartedAt.After(sess.StartedAt) {
			if sess.RootPID == root {
				return
			}
			sess.RootPID = root
			if ri, ok := r.tagger.Tag(root); ok && !ri.StartedAt.IsZero() {
				sess.RootStartedAt = ri.StartedAt.UTC().Format(time.RFC3339Nano)
			}
			r.upsertAndEmitLocked(sess)
			return
		}
	}
	if !r.joinTreeLocked(&sess, pid, info) {
		return
	}
	r.upsertAndEmitLocked(sess)
}

// isTraceKind reports the agent-semantic kinds only trace collectors emit.
// noteSightingLocked records a transcript or hook sighting of session id now.
// An empty harness keeps the one already recorded (SightedByHarness falls
// back to the stored session's).
func (r *Resolver) noteSightingLocked(id, harness string) {
	if id == "" {
		return
	}
	if harness == "" {
		harness = r.sighted[id].harness
	}
	now := r.now()
	r.sighted[id] = sighting{harness: harness, at: now}
	if len(r.sighted) > maxSightings {
		for k, v := range r.sighted {
			if now.Sub(v.at) > 24*time.Hour {
				delete(r.sighted, k)
			}
		}
	}
}

// SightedByHarness counts the sessions with a transcript or hook sighting at
// or after since, keyed by harness. A session whose process stayed alive
// without a new transcript line or hook event is not counted.
func (r *Resolver) SightedByHarness(since time.Time) map[string]int {
	r.mu.Lock()
	ids := map[string]string{}
	for id, v := range r.sighted {
		if !v.at.Before(since) {
			ids[id] = v.harness
		}
	}
	r.mu.Unlock()
	out := map[string]int{}
	for id, harness := range ids {
		if harness == "" {
			if sess, ok, err := r.st.GetSession(id); err == nil && ok {
				harness = sess.Harness
			}
		}
		if harness != "" {
			out[harness]++
		}
	}
	return out
}

func isTraceKind(k event.Kind) bool {
	switch k {
	case event.KindToolCall, event.KindTurn, event.KindModelCall:
		return true
	}
	return false
}

// emitLocked notifies delta subscribers of a session change (nil-safe).
func (r *Resolver) emitLocked(sess model.Session) {
	if r.OnSessionChange != nil {
		r.OnSessionChange(sess)
	}
}

// upsertAndEmitLocked publishes stored metadata only after its write succeeds.
// A failed save must not trigger a follow-up activity write. Caller holds mu.
func (r *Resolver) upsertAndEmitLocked(sess model.Session) bool {
	if err := r.st.UpsertSession(sess); err != nil {
		log.Printf("session: persist metadata: %v", err)
		return false
	}
	if saved, ok, err := r.st.GetSession(sess.ID); err == nil && ok {
		r.emitLocked(saved)
	}
	return true
}

// touchLocked bumps last_seen at most once per touchThrottle per session,
// persisting deferred sessions past the floor and retaining failed writes.
func (r *Resolver) touchLocked(id string, ts time.Time) {
	if ts.IsZero() {
		ts = r.now()
	}
	if last, ok := r.touch[id]; ok && ts.Sub(last) < touchThrottle {
		return
	}
	if sess, ok := r.deferred[id]; ok {
		if info, tagged := r.tagger.Tag(sess.RootPID); tagged && !info.StartedAt.IsZero() {
			if ts.Sub(info.StartedAt) < minSessionLifetime {
				r.touch[id] = ts
				return // still under the floor
			}
		} else if rootStart := rootStarted(sess); !rootStart.IsZero() && ts.Sub(rootStart) < minSessionLifetime {
			// An exited root that died young must not become a row.
			delete(r.deferred, id)
			r.touch[id] = ts
			return // root died before the floor
		}
		sess.LastSeenAt = ts
		if err := r.st.UpsertSession(sess); err != nil {
			log.Printf("session: persist deferred promotion: %v", err)
			return
		}
		delete(r.deferred, id)
		r.touch[id] = ts
		if saved, ok, err := r.st.GetSession(id); err == nil && ok {
			r.emitLocked(saved)
		}
		return
	}
	if err := r.st.TouchSession(id, ts); err != nil {
		log.Printf("session: persist activity: %v", err)
		return
	}
	r.touch[id] = ts
}

// rootStarted parses the root start time recorded at session creation
// (zero when unknown).
func rootStarted(sess model.Session) time.Time {
	if sess.RootStartedAt == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, sess.RootStartedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// WorkspaceFor returns the workspace recorded for a session id ("" if none) —
// so flags/incidents can carry the workspace that per-workspace notification
// scopes key on without a second resolution pass.
func (r *Resolver) WorkspaceFor(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	if sess, ok, err := r.st.GetSession(sessionID); err == nil && ok {
		return sess.Workspace
	}
	return ""
}

// PermissionIdentity binds the kernel-authenticated peer to the resolver's
// current session, not merely an existing client-supplied session ID.
func (r *Resolver) PermissionIdentity(pid int32, claimed string) (model.DecisionScope, bool) {
	info, ok := r.tagger.LiveFamily(pid)
	if !ok {
		return model.DecisionScope{}, false
	}
	r.mu.Lock()
	id := r.byRoot[info.PID]
	r.mu.Unlock()
	if id == "" || (claimed != "" && claimed != id) {
		return model.DecisionScope{}, false
	}
	sess, ok, err := r.st.GetSession(id)
	if err != nil || !ok || (sess.Status != model.SessionActive && sess.Status != model.SessionIdle) || sess.RootPID != info.PID || !rootStarted(sess).Equal(info.StartedAt) || sess.Harness != info.Name || sess.Workspace != info.CWD {
		return model.DecisionScope{}, false
	}
	return model.DecisionScope{Agent: info.Name, SessionID: id, Workspace: info.CWD, ReaderExe: info.ExePath, IdentityBasis: "peer-process-tree"}, true
}

// Sweep advances the lifecycle: active → idle after silence, idle → ended
// when the root process is gone (or after a day of silence for pid-less
// hook sessions, or an hour of silence on a root that now belongs to an
// infra family other than the session's harness). Call on the tagger
// refresh cadence.
func (r *Resolver) Sweep() {
	now := r.now()
	idled, err := r.st.MarkSessionsIdle(now.Add(-idleAfter))
	if err != nil {
		log.Printf("session: persist idle transitions: %v", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for root, id := range r.byRoot {
		// A root missing from one process-table sample is ended only when the
		// process source confirms it is gone or reused.
		sess, ok, err := r.lookupLocked(id)
		if err != nil {
			continue
		}
		var recorded time.Time
		if ok && sess.RootPID == root {
			recorded = rootStarted(sess)
		}
		if r.rootGone(root, recorded) {
			r.endLocked(id, now)
		}
	}
	// Sessions known to the store but not to the in-memory maps (daemon
	// restarted mid-session, or other conversations on a tracked root): end
	// those whose root is gone or reused, and end pid-less hook sessions
	// after a day of silence.
	for root, sessions := range r.st.SessionRoots() {
		for _, sess := range sessions {
			if r.byRoot[root] != sess.ID && r.rootGone(root, rootStarted(sess)) {
				r.endLocked(sess.ID, now)
			}
		}
	}
	sessions, err := r.st.ListSessions(store.SessionFilter{Status: model.SessionIdle, Limit: 500})
	if err != nil {
		return
	}
	for _, sess := range sessions {
		if sess.RootPID == 0 && now.Sub(sess.LastSeenAt) > endSilentAfter {
			r.endLocked(sess.ID, now)
		}
		// A root taken before the agents config named that process infra (a
		// Claude desktop conversation rooted at the app) outlives the
		// conversation; a stamped event re-roots a live one (joinTreeLocked),
		// so only a silent one is still on it.
		if sess.RootPID != 0 && now.Sub(sess.LastSeenAt) > endInfraRootAfter {
			if info, ok := r.tagger.Tag(sess.RootPID); ok && info.Kind == config.AgentKindInfra && info.Name != sess.Harness {
				r.endLocked(sess.ID, now)
			}
		}
	}
	// Idle transitions ride the delta stream too (the console's status chip
	// must move without a poll).
	for _, id := range idled {
		if sess, ok, err := r.st.GetSession(id); err == nil && ok {
			r.emitLocked(sess)
		}
	}
}

// endLocked ends session id and drops it from the in-memory maps. Caller
// holds mu.
func (r *Resolver) endLocked(id string, now time.Time) {
	if err := r.st.EndSession(id, now); err != nil {
		log.Printf("session: end tracked session: %v", err)
		return
	}
	if sess, ok, err := r.st.GetSession(id); err == nil && ok {
		r.emitLocked(sess)
	}
	delete(r.deferred, id)
	delete(r.touch, id)
	for root, sid := range r.byRoot {
		if sid == id {
			delete(r.byRoot, root)
		}
	}
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
