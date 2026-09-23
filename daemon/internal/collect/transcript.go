package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
)

const (
	// tailInterval is how often active transcript files are tailed for new lines.
	tailInterval = 200 * time.Millisecond
	// resolveInterval is how often the (expensive) recursive path discovery and
	// the active-set recomputation run.
	resolveInterval = 5 * time.Second
	// activeWindow is how recently a file must have been modified to be tailed
	// on the fast loop. Idle historical transcripts are skipped until they are
	// appended to again; they rejoin the active set within one resolveInterval,
	// and their byte offset is retained, so no appended lines are missed.
	activeWindow = 2 * time.Minute
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

	// ExtraTargets, when set, is consulted on every classify pass for
	// dynamically discovered targets (e.g. CODEX_HOME read off live codex
	// processes — a launcher that relocates the rollout store must not
	// blind the daemon until restart).
	ExtraTargets func() []string

	// Test seams; zero values pick the package constants.
	tailEvery     time.Duration
	resolveEvery  time.Duration
	activeWindowD time.Duration

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
func (ts *TranscriptScanner) scanLine(line, path, harness, sessionID string) []event.Event {
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
func (ts *TranscriptScanner) publishHits(line, path, harness, sessionID string) {
	for _, e := range ts.scanLine(line, path, harness, sessionID) {
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

	// seedFile sets an unseen file's offset to its current EOF. It must NEVER
	// touch a file already in the offsets map: resetting a live offset to EOF
	// discards whatever was appended since the last tail tick — on the resolve
	// cadence that skipped exactly the line that made an idle file active
	// again (the prompt).
	seedFile := func(p string) {
		if _, ok := offsets[p]; ok {
			return
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			offsets[p] = fi.Size()
		}
	}

	// Targets split two ways. Directory targets (e.g. ~/.claude/projects) need a
	// recursive walk that is expensive when the tree holds thousands of files,
	// so they are re-walked only on the slow resolve cadence and further limited
	// to recently-modified files. File and glob targets (the hook activity log,
	// session logs) are cheap to resolve and are refreshed on every fast tail
	// tick, so real-time signals are picked up with low latency. Walking the
	// whole tree on every tail tick previously pegged the CPU at ~20%.
	//
	// Pre-existing content is seeded past exactly once per directory target —
	// on its FIRST sighting (startup, or a dynamically discovered target).
	// Files created afterwards are read from byte 0 by tailFile, so a session
	// transcript that appears mid-run is captured whole while history is never
	// replayed.
	dirTargets, cheapTargets := ts.classifyTargets()
	cheapPaths := resolveGlobs(cheapTargets)
	for _, p := range cheapPaths {
		seedFile(p)
	}
	seededDirs := map[string]bool{}
	var allDirPaths, dirPaths []string
	dirty := false
	walk := func() {
		allDirPaths = allDirPaths[:0]
		for _, d := range dirTargets {
			files := walkDir(d)
			if !seededDirs[d] {
				seededDirs[d] = true
				for _, p := range files {
					seedFile(p)
				}
			}
			allDirPaths = append(allDirPaths, files...)
		}
		dirPaths = ts.activePaths(allDirPaths)
	}
	walk()

	tailTicker := time.NewTicker(tailEvery)
	defer tailTicker.Stop()
	resolveTicker := time.NewTicker(resolveEvery)
	defer resolveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resolveTicker.C:
			dirTargets, cheapTargets = ts.classifyTargets()
			walk()
			ts.saveOffsets(offsets)
		case <-tailTicker.C:
			cheapPaths = resolveGlobs(cheapTargets)
			live := make(map[string]struct{}, len(cheapPaths)+len(allDirPaths))
			for _, p := range cheapPaths {
				live[p] = struct{}{}
				ts.tailFile(p, offsets, &dirty)
			}
			for _, p := range dirPaths {
				live[p] = struct{}{}
				ts.tailFile(p, offsets, &dirty)
			}
			if dirty {
				dirty = false
				ts.saveOffsets(offsets)
			}
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
				}
			}
		}
	}
}

// classifyTargets splits configured targets into directory targets (which need
// a recursive walk) and cheap targets (explicit files or globs). A target that
// does not currently exist is treated as cheap; it costs nothing until it
// appears. Dynamic targets (ExtraTargets) are re-evaluated on every pass.
func (ts *TranscriptScanner) classifyTargets() (dirs, cheap []string) {
	paths := ts.paths
	if ts.ExtraTargets != nil {
		paths = append(append([]string{}, paths...), ts.ExtraTargets()...)
	}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			dirs = append(dirs, p)
		} else {
			cheap = append(cheap, p)
		}
	}
	return dirs, cheap
}

// walkDir returns every .jsonl file beneath one directory target.
func walkDir(dir string) []string {
	var res []string
	_ = filepath.WalkDir(dir, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		// agy writes the same steps three ways (transcript.jsonl,
		// transcript_full.jsonl, and chunk files); trace only the full
		// one so a step is never emitted — or redaction-scanned — twice.
		if strings.Contains(filepath.ToSlash(path), "/antigravity-cli/brain/") {
			if !strings.HasSuffix(path, "/transcript_full.jsonl") {
				return nil
			}
		}
		res = append(res, path)
		return nil
	})
	return res
}

// resolveGlobs expands explicit-file and glob targets to the files that exist
// now. A target with no match yet is returned as-is so tailFile can pick it up
// the moment it appears.
func resolveGlobs(targets []string) []string {
	var res []string
	for _, p := range targets {
		matches, err := filepath.Glob(p)
		if err == nil && len(matches) > 0 {
			for _, m := range matches {
				if fi, mErr := os.Stat(m); mErr == nil && !fi.IsDir() {
					res = append(res, m)
				}
			}
		} else {
			res = append(res, p)
		}
	}
	return res
}

// activePaths returns the subset of paths modified within the active window.
// It runs on the slow resolve cadence so the fast tail loop can skip the
// thousands of idle historical transcripts that never change; an idle file
// rejoins the set within one resolve interval of being appended to, and its
// offset is retained, so no appended lines are missed.
func (ts *TranscriptScanner) activePaths(paths []string) []string {
	window := ts.activeWindowD
	if window <= 0 {
		window = activeWindow
	}
	cutoff := time.Now().Add(-window)
	res := make([]string, 0, len(paths))
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		if fi.ModTime().After(cutoff) {
			res = append(res, p)
		}
	}
	return res
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
						ts.publishHits(line, p, "claude", evs[0].SessionID)
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
						if ts.codexTracers == nil {
							ts.codexTracers = map[string]*CodexTracer{}
						}
						ts.codexTracers[p] = tracer
					}
					if evs, ok := tracer.ParseLine(line); ok {
						sid, cwd := tracer.Session()
						if sid != "" && ts.OnSessionSeen != nil {
							ts.OnSessionSeen(sid, "codex", cwd, time.Now())
						}
						for _, e := range evs {
							ts.bus.Publish(e)
						}
						if len(evs) > 0 && ts.OnProduce != nil {
							ts.OnProduce()
						}
						ts.publishHits(line, p, "codex", sid)
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
						ts.publishHits(line, p, "cursor", sid)
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
						ts.publishHits(line, p, "agy", sid)
						continue
					}
				}
				if evs := ts.scanLine(line, p, harnessForPath(p), ts.knownSession(p)); len(evs) > 0 {
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
