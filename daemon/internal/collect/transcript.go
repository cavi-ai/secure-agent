package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
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
				Kind:      event.KindTranscriptHit,
				TS:        now,
				Path:      path,
				SessionID: sessionID,
				Detail:    harness + ":" + h.layer + ":" + h.rule,
				Offset:    lineStart,
			})
		}
		return evs
	}
	if e, ok := parsePluginLine(line); ok {
		return []event.Event{e}
	}
	return nil
}

type secretHit struct{ layer, rule string }

// secretHits returns the layer and rule id of each secret in line. Entropy
// hits are dropped: transcripts are dense with ids, hashes and encoded blobs.
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
			out = append(out, secretHit{layer: "pattern", rule: h.RuleID})
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

// publishHits publishes the transcript-hit events in a trace line; the
// tracer has already published the line's trace events.
func (ts *TranscriptScanner) publishHits(line, path, harness, sessionID string, lineStart int64) {
	for _, e := range ts.scanLine(line, path, harness, sessionID, lineStart) {
		if e.Kind == event.KindTranscriptHit {
			ts.bus.Publish(e)
		}
	}
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

// knownSession returns the session id a tracer already holds for path.
func (ts *TranscriptScanner) knownSession(p string) string {
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
				files = globFiles(tgt, os.ReadDir)
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
		active = activePaths(shaped, now, window)
		// Prune offsets only for files that no longer EXIST (deleted or
		// rotated out). Pruning inactive-but-present files forced a byte-0
		// re-read the moment they were appended to again — the duplicate
		// replay bug.
		for p := range offsets {
			if _, ok := live[p]; ok {
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
			for _, p := range explicit {
				ts.tailFile(p, offsets, &dirty)
			}
			for _, p := range active {
				ts.tailFile(p, offsets, &dirty)
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

func (ts *TranscriptScanner) tailFile(p string, offsets map[string]int64, dirty *bool) {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return
	}

	offset, tracked := offsets[p]
	if !tracked {
		// New file discovered after startup: tail from byte 0
		offset = 0
	}

	if fi.Size() < offset {
		offset = 0 // file truncated
	}
	if fi.Size() == offset {
		return // no new data
	}

	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}

	r := bufio.NewReaderSize(f, 1024*1024)
	newOffset := offset

	for {
		// ReadSlice with fragments assembled into one line: transcript lines
		// exceed the reader's buffer (real prompts run 10 KB+), and dropping
		// overlong lines silently skipped exactly the long human-prompt
		// records — turn detection never saw them. A newline-less multi-MB
		// line is still capped and skipped.
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
			if err == nil { // complete line (ended with \n): advance past it
				newOffset += lineLen
			}
		} else if len(frag) > 0 {
			if bytes.HasSuffix(frag, []byte("\n")) {
				newOffset += lineLen
				lineStart := newOffset - lineLen
				line := strings.TrimRight(string(frag), "\r\n")
				if h, ok := ParseHandshake(line); ok {
					if ts.OnHandshake != nil {
						ts.OnHandshake(h)
					}
					// Also publish as a plugin action: the handshake is hook
					// activity (coverage signal) and belongs on the timeline.
					evt := event.Event{Kind: event.KindPluginAction, PID: h.PID, SessionID: h.SessionID, Detail: "session-start"}
					if t, err := time.Parse(time.RFC3339Nano, h.TS); err == nil {
						evt.TS = t
					} else {
						evt.TS = time.Now()
					}
					ts.bus.Publish(evt)
					if ts.OnProduce != nil {
						ts.OnProduce()
					}
					continue
				}
				// Claude Code transcripts carry the trace: model calls with
				// usage, tool calls with durations, turn boundaries.
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
						for _, e := range evs {
							ts.bus.Publish(e)
						}
						if ts.OnProduce != nil {
							ts.OnProduce()
						}
						if ts.OnSessionSeen != nil {
							ts.OnSessionSeen(evs[0].SessionID, "claude", cwd, evs[0].TS)
						}
						// Trace lines still get the secret scan — an
						// assistant message can carry a secret in its text.
						ts.publishHits(line, p, "claude", evs[0].SessionID, lineStart)
						continue
					}
					// Not a trace record: still run the redaction scan.
				}
				// Codex rollouts carry the same trace shape through their own
				// envelope (token_count deltas, function_call pairing).
				if IsCodexRolloutPath(p) {
					tracer := ts.codexTracers[p]
					if tracer == nil {
						tracer = NewCodexTracer()
						if offset > 0 {
							// Resumed mid-file: the head holds the session
							// and model this run has not read.
							tracer.Prime(io.NewSectionReader(f, 0, offset))
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
						if sid != "" && ts.OnSessionSeen != nil {
							ts.OnSessionSeen(sid, "codex", cwd, time.Now())
						}
						for _, e := range evs {
							ts.bus.Publish(e)
						}
						if len(evs) > 0 && ts.OnProduce != nil {
							ts.OnProduce()
						}
						ts.publishHits(line, p, "codex", sid, lineStart)
						continue
					}
				}
				// Cursor agent transcripts: tool calls + turns (no
				// timestamps, no result pairing, no token usage).
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
						for _, e := range evs {
							ts.bus.Publish(e)
						}
						if ts.OnProduce != nil {
							ts.OnProduce()
						}
						ts.publishHits(line, p, "cursor", sid, lineStart)
						continue
					}
				}
				// Antigravity (agy) transcripts: tool calls + turns.
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
						for _, e := range evs {
							ts.bus.Publish(e)
						}
						if ts.OnProduce != nil {
							ts.OnProduce()
						}
						ts.publishHits(line, p, "agy", sid, lineStart)
						continue
					}
				}
				if evs := ts.scanLine(line, p, harnessForPath(p), ts.knownSession(p), lineStart); len(evs) > 0 {
					for _, e := range evs {
						ts.bus.Publish(e)
					}
					if ts.OnProduce != nil {
						ts.OnProduce()
					}
				}
			} else {
				// Partial line at EOF; do not advance past partial line, retry on next poll
				break
			}
		}
		if err != nil {
			break
		}
	}

	offsets[p] = newOffset
	if newOffset != offset && dirty != nil {
		*dirty = true
	}
}
