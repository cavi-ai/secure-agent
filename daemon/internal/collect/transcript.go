package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
	"github.com/cavi-ai/secure-agent/daemon/internal/testvalue"
)

const (
	// tailInterval is how often the active set and the explicit file targets
	// are tailed for new lines.
	tailInterval = time.Second
	// resolveInterval is how often the glob and directory targets are
	// re-expanded and the active set recomputed from that pass's stats.
	resolveInterval = 15 * time.Second
	// activeWindow is how recently a file must have been modified to be tailed
	// on the fast loop. Idle historical transcripts are skipped until they are
	// appended to again; they rejoin the active set within one resolveInterval,
	// and their byte offset is retained, so no appended lines are missed.
	activeWindow = 2 * time.Minute
	// offsetSaveInterval bounds how often the tail offsets are persisted.
	offsetSaveInterval = 30 * time.Second
	// hitDedupeWindow collapses repeats of the same (path, rule id) secret
	// hit: a transcript that quotes one secret on every turn is one finding.
	hitDedupeWindow = 10 * time.Minute
)

// TextScanner finds secrets in free text and reports them by rule id.
// *firewall.Engine satisfies it (known-secret fingerprints + typed patterns).
type TextScanner interface {
	ScanText(text string) []firewall.Hit
}

type TranscriptScanner struct {
	bus   *bus.Bus
	paths []string

	// One parsed line per blocked file, owned by the single tail loop. Parser
	// state and hit dedupe advance only once; the source checkpoint advances
	// only after the line's events have all been accepted by the bus.
	pending map[string]*pendingTranscriptLine

	// OffsetStatePath, when set, persists tail offsets across daemon
	// restarts. Without it a restart re-seeds every transcript at EOF and
	// lines appended while the daemon was down are never read.
	OffsetStatePath string

	// ExtraTargets, when set, is consulted on every resolve pass for
	// dynamically discovered targets (e.g. CODEX_HOME read off live codex
	// processes — a launcher that relocates the rollout store must not
	// blind the daemon until restart).
	ExtraTargets func() []string

	// Test seams; zero values pick the package constants.
	tailEvery     time.Duration
	resolveEvery  time.Duration
	activeWindowD time.Duration
	saveEvery     time.Duration
	readDir       readDirFunc // nil: os.ReadDir

	// OnProduce, when set, is called after any transcript/plugin event is
	// published — the supervisor's coverage heartbeat: a scanner whose
	// harnesses never emit hook events must not read as healthy coverage.
	OnProduce func()

	// OnHandshake, when set, receives the hook's session-start announcements
	// (harness, workspace, repo, branch, harness pid) so the session resolver
	// can register the authoritative session record.
	OnHandshake func(Handshake)

	// OnSessionSeen, when set, reports a session id sighted in a harness
	// transcript, with the harness name and workspace — transcript-tier
	// resolution and the join key to the process-tree session for the same
	// harness+workspace.
	OnSessionSeen func(sessionID, harness, workspace string, at time.Time)

	// OnCodexSessionSeen, when set, reports a Codex rollout's session with
	// its workspace and CodexOrigin (who spawned it; "" for the user's own).
	OnCodexSessionSeen func(sessionID, workspace, origin string, at time.Time)

	// TextScanner, when set, scans every tailed line for known and typed
	// secrets. Nil falls back to the redact package's patterns.
	TextScanner TextScanner

	// hitSeen records when each (path, rule id) secret hit was last emitted,
	// for hitDedupeWindow. The tail loop is single-goroutine, so no lock.
	hitSeen map[string]time.Time

	// tracers hold per-file Claude trace state (open tool_use ids). The
	// scanner's tail loop is single-goroutine, so no lock.
	tracers map[string]*ClaudeTracer
	// codexTracers hold per-file Codex rollout state (call_id pairing,
	// session id from session_meta).
	codexTracers map[string]*CodexTracer
	// cursorTracers hold per-file Cursor transcript state (session id from
	// the filename; Cursor has no pairing or usage to track).
	cursorTracers map[string]*CursorTracer
	// agyTracers hold per-file Antigravity transcript state (session id from
	// the brain directory; tools + turns only).
	agyTracers map[string]*AGYTracer

	// rolloutIDs maps a codex rollout path to the session id its session_meta
	// names, for the open-rollout joiner, which runs on its own goroutine.
	rolloutMu  sync.Mutex
	rolloutIDs map[string]string
}

// RolloutSession names the session a codex rollout belongs to: the id its
// session_meta line carries once the tracer has read it, else the id in the
// file name. Safe for concurrent use.
func (ts *TranscriptScanner) RolloutSession(path string) string {
	ts.rolloutMu.Lock()
	id := ts.rolloutIDs[path]
	ts.rolloutMu.Unlock()
	if id != "" {
		return id
	}
	return RolloutSessionID(path)
}

// noteRolloutSession records the session id a rollout's session_meta names.
func (ts *TranscriptScanner) noteRolloutSession(path, id string) {
	ts.rolloutMu.Lock()
	defer ts.rolloutMu.Unlock()
	if ts.rolloutIDs == nil {
		ts.rolloutIDs = map[string]string{}
	}
	ts.rolloutIDs[path] = id
}

// Handshake is the hook's session announcement line
// ({"type":"session_start", ...}) as parsed off the activity log.
type Handshake struct {
	SessionID string `json:"session_id"`
	Harness   string `json:"harness"`
	Workspace string `json:"workspace"`
	Repo      string `json:"repo"`
	Branch    string `json:"branch"`
	PID       int32  `json:"pid"`
	TS        string `json:"ts"`
}

// ParseHandshake recognizes session_start lines. Kept separate from scanLine
// so the secret scan never misfires on handshake metadata.
func ParseHandshake(line string) (Handshake, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, `"session_start"`) {
		return Handshake{}, false
	}
	var h struct {
		Type string `json:"type"`
		Handshake
	}
	if err := json.Unmarshal([]byte(trimmed), &h); err != nil || h.Type != "session_start" || h.SessionID == "" {
		return Handshake{}, false
	}
	return h.Handshake, true
}

func NewTranscriptScanner(b *bus.Bus, paths []string) *TranscriptScanner {
	return &TranscriptScanner{
		bus:   b,
		paths: paths,
	}
}

type pluginLogLine struct {
	Tool      string `json:"tool"`
	PID       int32  `json:"pid"`
	TS        string `json:"ts"`
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	FilePath  string `json:"file_path"`
}

// scanLine scans one tailed line for secrets. A line carrying a secret yields
// one transcript-hit event per (path, rule id) not already emitted within
// hitDedupeWindow — the path, session and rule id only, never the text — and
// is not parsed further. Any other line may be a hook activity record.
// lineStart is the byte offset of line in path.
func (ts *TranscriptScanner) scanLine(line, path, harness, sessionID string, lineStart int64) []event.Event {
	if line == "" {
		return nil
	}
	if hits := ts.secretHits(line); len(hits) > 0 {
		now := time.Now()
		var evs []event.Event
		for _, h := range hits {
			if !ts.firstHit(path, h.rule, now) {
				continue
			}
			evs = append(evs, event.Event{
				Kind:        event.KindTranscriptHit,
				TS:          now,
				Path:        path,
				SessionID:   sessionID,
				Detail:      harness + ":" + h.layer + ":" + h.rule,
				Offset:      lineStart,
				TestSignals: strings.Join(h.signals, "; "),
			})
		}
		return evs
	}
	if e, ok := parsePluginLine(line); ok {
		return []event.Event{e}
	}
	return nil
}

type secretHit struct {
	layer, rule string
	// signals are why a pattern hit's value looks like a test value.
	signals []string
}

// secretHits returns the layer and rule id of each secret in line, and for a
// pattern hit the test-value signals of its matches. Entropy hits are
// dropped: transcripts are dense with ids, hashes and encoded blobs.
func (ts *TranscriptScanner) secretHits(line string) []secretHit {
	if ts.TextScanner == nil {
		if rule, found := redact.Detect(line); found {
			return []secretHit{{layer: "pattern", rule: rule}}
		}
		return nil
	}
	var out []secretHit
	for _, h := range ts.TextScanner.ScanText(line) {
		switch h.Layer {
		case firewall.LayerFingerprint:
			out = append(out, secretHit{layer: "fingerprint", rule: h.RuleID})
		case firewall.LayerPattern:
			out = append(out, secretHit{layer: "pattern", rule: h.RuleID, signals: testSignals(line, h.Spans)})
		}
	}
	return out
}

// testSignals unions the test-value signals of a hit's matches, or returns
// nil when any match has none: one live-looking value outweighs fixtures
// beside it.
func testSignals(line string, spans [][2]int) []string {
	var out []string
	for _, sp := range spans {
		reasons := testvalue.Signals(line, sp[0], sp[1])
		if len(reasons) == 0 {
			return nil
		}
		for _, r := range reasons {
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	return out
}

// firstHit reports whether (path, rule) was not emitted within
// hitDedupeWindow, recording it when new. Expired entries are pruned on insert.
func (ts *TranscriptScanner) firstHit(path, rule string, now time.Time) bool {
	key := path + "\x00" + rule
	if last, ok := ts.hitSeen[key]; ok && now.Sub(last) < hitDedupeWindow {
		return false
	}
	if ts.hitSeen == nil {
		ts.hitSeen = map[string]time.Time{}
	}
	for k, at := range ts.hitSeen {
		if now.Sub(at) >= hitDedupeWindow {
			delete(ts.hitSeen, k)
		}
	}
	ts.hitSeen[key] = now
	return true
}

// transcriptHits returns only the security findings from a trace line.
// Delivery shares the trace line's checkpoint and retry state.
func (ts *TranscriptScanner) transcriptHits(line, path, harness, sessionID string, lineStart int64) []event.Event {
	var hits []event.Event
	for _, e := range ts.scanLine(line, path, harness, sessionID, lineStart) {
		if e.Kind == event.KindTranscriptHit {
			hits = append(hits, e)
		}
	}
	return hits
}

// harnessForPath names the harness whose transcript layout the path matches;
// "unknown" for hook activity logs and other tailed files.
func harnessForPath(p string) string {
	switch {
	case IsClaudeTranscriptPath(p):
		return "claude"
	case IsCodexRolloutPath(p):
		return "codex"
	case IsCursorTranscriptPath(p):
		return "cursor"
	case IsAGYTranscriptPath(p):
		return "agy"
	}
	return "unknown"
}

// knownSession returns the session id a tracer already holds for path. A
// Claude record that emits nothing (a repeat of a call already emitted) falls
// through to the plain scan and keeps its session this way.
func (ts *TranscriptScanner) knownSession(p string) string {
	if t := ts.tracers[p]; t != nil {
		return t.Session()
	}
	if t := ts.codexTracers[p]; t != nil {
		id, _ := t.Session()
		return id
	}
	if t := ts.cursorTracers[p]; t != nil {
		id, _ := t.Session()
		return id
	}
	if t := ts.agyTracers[p]; t != nil {
		id, _ := t.Session()
		return id
	}
	return ""
}

// parsePluginLine recognizes a hook activity record ({"tool": ...}).
func parsePluginLine(line string) (event.Event, bool) {
	if !strings.HasPrefix(strings.TrimSpace(line), "{") || !strings.Contains(line, `"tool"`) {
		return event.Event{}, false
	}
	var pl pluginLogLine
	if err := json.Unmarshal([]byte(line), &pl); err != nil || pl.Tool == "" {
		return event.Event{}, false
	}
	ts := time.Now()
	if pl.TS != "" {
		if t, err := time.Parse(time.RFC3339Nano, pl.TS); err == nil {
			ts = t
		} else if t, err := time.Parse(time.RFC3339, pl.TS); err == nil {
			ts = t
		}
	}
	path := pl.FilePath
	if path == "" {
		path = pl.Command
	}
	return event.Event{
		Kind:      event.KindPluginAction,
		TS:        ts,
		PID:       pl.PID,
		SessionID: pl.SessionID,
		Path:      path,
		Detail:    pl.Tool,
	}, true
}

func (ts *TranscriptScanner) Run(ctx context.Context) error {
	offsets := ts.loadOffsets()

	tailEvery := ts.tailEvery
	if tailEvery <= 0 {
		tailEvery = tailInterval
	}
	resolveEvery := ts.resolveEvery
	if resolveEvery <= 0 {
		resolveEvery = resolveInterval
	}
	saveEvery := ts.saveEvery
	if saveEvery <= 0 {
		saveEvery = offsetSaveInterval
	}
	window := ts.activeWindowD
	if window <= 0 {
		window = activeWindow
	}

	// The offsets map holds one entry per transcript ever seen, so a changed
	// map is written at most once per saveEvery, and always on shutdown.
	dirty := false
	var lastSave time.Time
	save := func(now time.Time, force bool) {
		if !dirty || (!force && now.Sub(lastSave) < saveEvery) {
			return
		}
		ts.saveOffsets(offsets)
		dirty, lastSave = false, now
	}

	// seedFile sets an unseen file's offset to its current EOF. It must NEVER
	// touch a file already in the offsets map: resetting a live offset to EOF
	// discards whatever was appended since the last tail tick — on the resolve
	// cadence that skipped exactly the line that made an idle file active
	// again (the prompt).
	seedFile := func(f found) {
		if _, ok := offsets[f.path]; ok {
			return
		}
		offsets[f.path] = f.size
		dirty = true
	}

	// Targets split three ways. Glob targets describe where each harness
	// writes (HarnessTranscriptGlobs): each `*` is one directory level, so
	// discovery lists only the directories on those shapes, never the
	// unrelated files beside them. A directory target no shape describes is
	// walked recursively, which reads its whole tree. Both are re-resolved
	// only on the slow resolve cadence, and the fast tail tick visits just
	// the files that pass found modified within the active window. Explicit
	// file targets (the hook activity log, the daemon's JSONL sink) are cheap
	// and tailed on every tick, so real-time signals keep low latency.
	//
	// Pre-existing content is seeded past exactly once per target — on its
	// FIRST sighting (startup, or a dynamically discovered target). Files
	// created afterwards are read from byte 0 by tailFile, so a session
	// transcript that appears mid-run is captured whole while history is never
	// replayed.
	sighted := map[string]bool{}
	walkLogged := map[string]bool{}
	read := ts.readDir
	if read == nil {
		read = os.ReadDir
	}
	// Glob targets list a directory again only when its mtime moved.
	dirs := newDirCache(read)
	var explicit, active []string
	resolve := func() {
		now := time.Now()
		explicit = explicit[:0]
		var shaped []found
		live := map[string]struct{}{}
		for _, tgt := range ts.targets() {
			first := !sighted[tgt]
			sighted[tgt] = true
			var files []found
			isExplicit := false
			switch {
			case hasMeta(tgt):
				files = globFiles(tgt, dirs.readDir)
			case isDir(tgt):
				if !walkLogged[tgt] {
					walkLogged[tgt] = true
					log.Printf("collect: transcript target %s is a directory no harness shape describes; it is walked on every resolve pass, which is expensive for a large tree", tgt)
				}
				files = walkDir(tgt)
			default:
				isExplicit = true
				explicit = append(explicit, tgt)
				if f, ok := statFile(tgt); ok {
					files = []found{f}
				}
			}
			for _, f := range files {
				if first {
					seedFile(f)
				}
				if _, dup := live[f.path]; dup {
					continue
				}
				live[f.path] = struct{}{}
				if !isExplicit {
					shaped = append(shaped, f)
				}
			}
		}
		dirs.sweep()
		active = activePaths(shaped, now, window)
		// Prune offsets only for files that no longer EXIST (deleted or
		// rotated out). Pruning inactive-but-present files forced a byte-0
		// re-read the moment they were appended to again — the duplicate
		// replay bug.
		for p := range offsets {
			if _, ok := live[p]; ok || ts.pending[p] != nil {
				continue
			}
			if _, err := os.Stat(p); err != nil {
				delete(offsets, p)
				dirty = true
			}
		}
	}
	resolve()

	tailTicker := time.NewTicker(tailEvery)
	defer tailTicker.Stop()
	resolveTicker := time.NewTicker(resolveEvery)
	defer resolveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			save(time.Now(), true)
			return ctx.Err()
		case <-resolveTicker.C:
			resolve()
			save(time.Now(), false)
		case <-tailTicker.C:
			tailed := make(map[string]bool, len(explicit)+len(active)+len(ts.pending))
			tail := func(p string) {
				if tailed[p] {
					return
				}
				tailed[p] = true
				ts.tailFile(p, offsets, &dirty)
			}
			for _, p := range explicit {
				tail(p)
			}
			for _, p := range active {
				tail(p)
			}
			// A staged line remains deliverable if its source becomes idle,
			// disappears, or no longer matches a dynamic discovery target.
			for p := range ts.pending {
				tail(p)
			}
			save(time.Now(), false)
		}
	}
}

// targets returns the configured targets plus the dynamic ones
// (ExtraTargets), re-evaluated on every resolve pass.
func (ts *TranscriptScanner) targets() []string {
	if ts.ExtraTargets == nil {
		return ts.paths
	}
	return append(append([]string{}, ts.paths...), ts.ExtraTargets()...)
}

// loadOffsets reads persisted tail offsets written by a previous daemon run.
// A corrupt or unreadable file is ignored — worst case is a re-seed at EOF,
// the pre-persistence behavior.
func (ts *TranscriptScanner) loadOffsets() map[string]int64 {
	offsets := make(map[string]int64)
	if ts.OffsetStatePath == "" {
		return offsets
	}
	data, err := os.ReadFile(ts.OffsetStatePath)
	if err != nil {
		return offsets
	}
	var saved map[string]int64
	if err := json.Unmarshal(data, &saved); err != nil {
		return offsets
	}
	for p, off := range saved {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() >= off {
			offsets[p] = off
		}
	}
	return offsets
}

// saveOffsets persists the tail offsets. Best-effort: a failed write loses
// at most one restart's worth of appended lines.
func (ts *TranscriptScanner) saveOffsets(offsets map[string]int64) {
	if ts.OffsetStatePath == "" {
		return
	}
	data, err := json.Marshal(offsets)
	if err != nil {
		return
	}
	tmp := ts.OffsetStatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, ts.OffsetStatePath)
}

type pendingTranscriptLine struct {
	nextOffset int64
	events     []event.Event
}

func setTranscriptOffset(p string, offsets map[string]int64, next int64, dirty *bool) {
	previous, tracked := offsets[p]
	offsets[p] = next
	if (!tracked || previous != next) && dirty != nil {
		*dirty = true
	}
}

// deliverPending never waits for the consumer. Accepted prefixes are removed
// from the staged line, so a retry cannot duplicate them in this daemon run.
func (ts *TranscriptScanner) deliverPending(p string, offsets map[string]int64, dirty *bool) bool {
	pending := ts.pending[p]
	if pending == nil {
		return true
	}
	produced := false
	defer func() {
		if produced && ts.OnProduce != nil {
			ts.OnProduce()
		}
	}()
	for len(pending.events) > 0 {
		if !ts.bus.TryPublish(pending.events[0]) {
			return false
		}
		pending.events[0] = event.Event{}
		pending.events = pending.events[1:]
		produced = true
	}
	setTranscriptOffset(p, offsets, pending.nextOffset, dirty)
	delete(ts.pending, p)
	return true
}

func (ts *TranscriptScanner) tailFile(p string, offsets map[string]int64, dirty *bool) {
	if !ts.deliverPending(p, offsets, dirty) {
		return
	}
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return
	}
	offset := offsets[p]
	if fi.Size() < offset {
		offset = 0
	}
	if fi.Size() == offset {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}
	// Persist byte zero for a new file even when its first event is rejected.
	// Without this entry, restart discovery would seed past it at EOF.
	setTranscriptOffset(p, offsets, offset, dirty)
	r := bufio.NewReaderSize(f, 1024*1024)
	nextOffset := offset
	for {
		// Assemble fragments up to the line cap. Skip only complete oversized
		// lines; a partial line keeps its checkpoint for the next poll.
		var lineLen int64
		var frag []byte
		var err error
		overlong := false
		for {
			frag, err = r.ReadSlice('\n')
			lineLen += int64(len(frag))
			if err == bufio.ErrBufferFull {
				overlong = true
				continue
			}
			break
		}
		if overlong {
			if err == nil {
				nextOffset += lineLen
				setTranscriptOffset(p, offsets, nextOffset, dirty)
			}
		} else if len(frag) > 0 {
			if !bytes.HasSuffix(frag, []byte("\n")) {
				break
			}
			lineStart := nextOffset
			nextOffset += lineLen
			line := strings.TrimRight(string(frag), "\r\n")
			events := ts.eventsForLine(p, line, lineStart, offset, f)
			if len(events) == 0 {
				setTranscriptOffset(p, offsets, nextOffset, dirty)
			} else {
				if ts.pending == nil {
					ts.pending = make(map[string]*pendingTranscriptLine)
				}
				ts.pending[p] = &pendingTranscriptLine{nextOffset: nextOffset, events: events}
				if !ts.deliverPending(p, offsets, dirty) {
					return
				}
			}
		}
		if err != nil {
			break
		}
	}
}

// eventsForLine parses a complete bounded line once. Session sightings still
// describe observed source activity; OnProduce describes accepted delivery.
func (ts *TranscriptScanner) eventsForLine(p, line string, lineStart, offset int64, source io.ReaderAt) []event.Event {
	if h, ok := ParseHandshake(line); ok {
		if ts.OnHandshake != nil {
			ts.OnHandshake(h)
		}
		e := event.Event{Kind: event.KindPluginAction, PID: h.PID, SessionID: h.SessionID, Detail: "session-start"}
		if at, err := time.Parse(time.RFC3339Nano, h.TS); err == nil {
			e.TS = at
		} else {
			e.TS = time.Now()
		}
		return []event.Event{e}
	}
	if IsClaudeTranscriptPath(p) {
		tracer := ts.tracers[p]
		if tracer == nil {
			tracer = NewClaudeTracer()
			if ts.tracers == nil {
				ts.tracers = map[string]*ClaudeTracer{}
			}
			ts.tracers[p] = tracer
		}
		if evs, cwd, ok := tracer.ParseLine(line); ok {
			if ts.OnSessionSeen != nil {
				ts.OnSessionSeen(evs[0].SessionID, "claude", cwd, evs[0].TS)
			}
			return append(evs, ts.transcriptHits(line, p, "claude", evs[0].SessionID, lineStart)...)
		}
	}
	if IsCodexRolloutPath(p) {
		tracer := ts.codexTracers[p]
		if tracer == nil {
			tracer = NewCodexTracer(p)
			if offset > 0 {
				tracer.Prime(io.NewSectionReader(source, 0, offset))
			}
			if ts.codexTracers == nil {
				ts.codexTracers = map[string]*CodexTracer{}
			}
			ts.codexTracers[p] = tracer
		}
		if evs, ok := tracer.ParseLine(line); ok {
			sid, cwd := tracer.Session()
			if sid != "" {
				ts.noteRolloutSession(p, sid)
			}
			if sid != "" && ts.OnCodexSessionSeen != nil {
				ts.OnCodexSessionSeen(sid, cwd, CodexOrigin(p), time.Now())
			}
			return append(evs, ts.transcriptHits(line, p, "codex", sid, lineStart)...)
		}
	}
	if IsCursorTranscriptPath(p) {
		tracer := ts.cursorTracers[p]
		if tracer == nil {
			tracer = NewCursorTracer(p)
			if ts.cursorTracers == nil {
				ts.cursorTracers = map[string]*CursorTracer{}
			}
			ts.cursorTracers[p] = tracer
		}
		if evs, ok := tracer.ParseLine(line); ok {
			sid, ws := tracer.Session()
			if sid != "" && ts.OnSessionSeen != nil {
				ts.OnSessionSeen(sid, "cursor", ws, evs[0].TS)
			}
			return append(evs, ts.transcriptHits(line, p, "cursor", sid, lineStart)...)
		}
	}
	if IsAGYTranscriptPath(p) {
		tracer := ts.agyTracers[p]
		if tracer == nil {
			tracer = NewAGYTracer(p)
			if ts.agyTracers == nil {
				ts.agyTracers = map[string]*AGYTracer{}
			}
			ts.agyTracers[p] = tracer
		}
		if evs, ok := tracer.ParseLine(line); ok {
			sid, ws := tracer.Session()
			if sid != "" && ts.OnSessionSeen != nil {
				ts.OnSessionSeen(sid, "agy", ws, evs[0].TS)
			}
			return append(evs, ts.transcriptHits(line, p, "agy", sid, lineStart)...)
		}
	}
	return ts.scanLine(line, p, harnessForPath(p), ts.knownSession(p), lineStart)
}
