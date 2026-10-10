package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// spoolDrainBudget bounds how many bytes drainOnce will scan and attempt to
// parse in one tick. A defective privileged writer can grow the spool by
// tens of MB per second with near-empty garbage lines: without a budget,
// every tick would pay bufio.Scanner plus the parser over the whole flood.
// Past the budget the rest of the tail is skipped in bulk — counted, never
// scanned line by line.
const spoolDrainBudget = 4 << 20 // 4 MiB

// SpoolStats are the tailer's counters from its most recent drain. Lines and
// Parsed count only the lines the scanner actually read and attempted to
// parse — Skipped and BytesSkipped (lines and bytes dropped in bulk past the
// per-tick budget, never handed to the scanner) are NOT folded into Lines, so
// a burst of valid lines the tailer had to skip never reads as unparsed
// garbage. FloodSince is zero unless the tailer is currently having to skip;
// it is set the first tick that skips and cleared the first tick that drains
// fully within budget.
type SpoolStats struct {
	// BytesLost is a cumulative lower bound for unread bytes overwritten by
	// rotation or truncation during this run. A later healthy tick cannot
	// reconstruct that evidence or clear the gap.
	BytesLost uint64
	// LostAt is when BytesLost last grew (zero before any loss).
	LostAt       time.Time
	Lines        uint64
	Parsed       uint64
	Skipped      uint64
	BytesSkipped uint64
	FloodSince   time.Time
	// NewestEvent is the event time of the newest event the tailer has
	// published (zero before the first), kept across drains. Lag is how far
	// it trailed the clock when it was published; zero once that is older
	// than spoolLagFresh. ES rows are stored with their event time, so a
	// writer whose source queues events delivers them that late to every
	// flag and resource episode.
	NewestEvent time.Time
	Lag         time.Duration
}

// spoolLagFresh is how long a measured lag stays reportable without a newer
// published event.
const spoolLagFresh = 2 * time.Minute

// LossWindow is how long after its last increase a loss counter (spool bytes,
// bus drops) still counts as growing; Doctor and posture fail only then.
const LossWindow = 10 * time.Minute

// LossGrowing reports whether a loss counter last grew at `at` within
// LossWindow of now.
func LossGrowing(at, now time.Time) bool {
	return !at.IsZero() && now.Sub(at) < LossWindow
}

// The privileged ES collector's spool (the collector daemon writes it as root).
const ESPoolPath = "/var/db/secure-agent/es-spool.jsonl"

// ESServiceLabel is the root LaunchDaemon label running the privileged
// collector. The user daemon probes its real launchd state so posture can
// say "the root service is crash-looping" — the tailer being alive proves
// nothing about the writer.
const ESServiceLabel = "com.cavi-ai.secure-agent-esd"

// SpoolAvailable reports whether the privileged ES collector's spool (or,
// mid-rotation, its .1) exists and is readable by this (unprivileged)
// daemon — the signal that file telemetry should come from the spool tail
// instead of a direct eslogger child (which macOS only permits as root).
func SpoolAvailable() bool {
	return spoolAvailableAt(ESPoolPath)
}

func spoolAvailableAt(path string) bool {
	for _, p := range []string{path, path + ".1"} {
		if f, err := os.Open(p); err == nil {
			_ = f.Close()
			return true
		}
	}
	return false
}

// spoolFacts is the spool's size and mtime. Rotation renames the spool to
// <path>.1 before it creates the new one; in that gap <path>.1 is the newest
// spool, so a probe landing there does not read as a missing collector.
// Zero values when neither file exists.
func spoolFacts(path string) (int64, time.Time) {
	for _, p := range []string{path, path + ".1"} {
		if st, err := os.Stat(p); err == nil {
			return st.Size(), st.ModTime()
		}
	}
	return 0, time.Time{}
}

// ESServiceSnapshot is one probe of the privileged collector's real state:
// the launchd service state string, the spool's size and mtime, and the
// mtime of the program launchd runs for it (zero when absent). The probe is injectable
// (ESServiceProbe) so tests never shell out.
type ESServiceSnapshot struct {
	BytesLost   uint64    `json:"bytes_lost"`
	State       string    `json:"state"`
	SpoolSize   int64     `json:"spool_size"`
	SpoolMtime  time.Time `json:"spool_mtime"`
	HelperMtime time.Time `json:"helper_mtime"`

	// Flooding and UnparsedShare come from the tailer's drain stats (nil
	// when the daemon does not tail a spool): Flooding is true while the
	// tailer is having to skip past its per-tick budget; UnparsedShare is
	// the fraction of lines in the last drain that did not parse.
	// BytesSkipped is how many tail bytes the last drain skipped in bulk.
	// FloodingSince is nil unless Flooding is true; it carries the tailer's
	// SpoolStats.FloodSince so posture/doctor can tell a short burst (normal
	// load) from a reader that has been falling behind for a while.
	Flooding      bool       `json:"flooding"`
	UnparsedShare float64    `json:"unparsed_share"`
	BytesSkipped  uint64     `json:"bytes_skipped"`
	FloodingSince *time.Time `json:"flooding_since,omitempty"`
	// NewestEventAt and LagSeconds carry SpoolStats.NewestEvent and Lag: how
	// late file events reach the daemon, whatever the spool's own mtime says.
	NewestEventAt *time.Time `json:"newest_event_at,omitempty"`
	// LostAt is when BytesLost last grew; Losing is true within LossWindow
	// of it.
	LostAt     *time.Time `json:"lost_at,omitempty"`
	Losing     bool       `json:"losing,omitempty"`
	LagSeconds int64      `json:"lag_seconds"`
}

// SpoolState renders the spool facts for humans ("3.2 MB, updated 12 min ago").
func (s ESServiceSnapshot) SpoolState() string {
	return s.SpoolStateAt(time.Now())
}

// SpoolStateAt renders the snapshot relative to a captured observation time.
func (s ESServiceSnapshot) SpoolStateAt(now time.Time) string {
	if s.SpoolSize == 0 && s.SpoolMtime.IsZero() {
		return "absent"
	}
	return fmt.Sprintf("%d bytes, updated %s ago", s.SpoolSize, now.Sub(s.SpoolMtime).Round(time.Second))
}

// ESServiceProbe is the function posture calls to read the root service's
// real state. Overridable in tests; production uses ESServiceState.
var ESServiceProbe = ESServiceState

// ESServiceState probes the privileged collector's real health the only way
// an unprivileged daemon can: stat the spool (size + mtime), read the
// launchd service state via launchctl print, and stat the program that
// output names (mtime). Spawning/exit != 0 with a stale spool is the
// crash-loop signature (rapid respawns while the tailer reports running).
func ESServiceState() (ESServiceSnapshot, error) {
	var s ESServiceSnapshot
	s.SpoolSize, s.SpoolMtime = spoolFacts(ESPoolPath)
	out, cerr := exec.Command("/bin/launchctl", "print", "system/"+ESServiceLabel).Output()
	if cerr != nil {
		// Not loaded / not running as root: report the file facts anyway.
		s.State = "not-loaded"
		return s, nil
	}
	s.State = parseLaunchctlState(string(out))
	s.HelperMtime = helperMtime(string(out))
	return s, nil
}

// helperMtime stats the program named on the top-level `program =` line of
// `launchctl print` output; zero when the line or the file is absent.
func helperMtime(out string) time.Time {
	program := parseLaunchctlProgram(out)
	if program == "" {
		return time.Time{}
	}
	st, err := os.Stat(program)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// parseLaunchctlProgram returns the absolute path on the top-level
// `program =` line of `launchctl print` output, or "" when there is none.
// Same indentation rule as parseLaunchctlState.
func parseLaunchctlProgram(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		if program, ok := strings.CutPrefix(strings.TrimSpace(line), "program = "); ok && filepath.IsAbs(program) {
			return program
		}
	}
	return ""
}

// parseLaunchctlState extracts the service state from `launchctl print`
// output. Top-level keys sit at exactly one tab of indentation; nested
// sections (endpoints, mach services) carry their own `state =` lines,
// which must not overwrite the service state — first top-level match wins.
// A nonzero last exit code rides along as an annotation.
func parseLaunchctlState(out string) string {
	state := "running"
	exitNote := ""
	seenState := false
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !seenState && strings.HasPrefix(trimmed, "state = ") {
			state = strings.TrimPrefix(trimmed, "state = ")
			seenState = true
		} else if strings.HasPrefix(trimmed, "last exit code = ") {
			code := strings.TrimPrefix(trimmed, "last exit code = ")
			if code != "0" && code != "(never exited)" {
				exitNote = " (last exit " + code + ")"
			}
		}
	}
	return state + exitNote
}

// SpoolTailer consumes the privileged ES collector's spool file and publishes
// each line as an event. Same parser, same bus — the only difference from
// ESLogger is where the bytes come from: a root-written file instead of a
// root-required child process.
//
// Poll-reopen model (simple, rotation-proof): every 200ms, stat the file;
// when its size or mtime moved, open it, skip to the last-read offset, emit
// new lines, remember the offset. A rotated/truncated/missing file resets
// the offset to "read what exists now". At 200ms granularity the latency
// cost is negligible next to the correlator's own windows.
type SpoolTailer struct {
	bus  *bus.Bus
	path string

	// open is the file opener; nil means os.Open (test seam).
	open func(string) (*os.File, error)
	// retained belongs to the single poll loop; it distinguishes valid
	// backlog from a partial line in a file the writer has rotated.
	retained bool

	// OnProduce, when set, is called after any spool event is published —
	// the supervisor's coverage heartbeat: a tailer whose spool stopped
	// growing must not read as healthy coverage.
	OnProduce func()

	statsMu sync.Mutex
	stats   SpoolStats
	lost    uint64
	lostAt  time.Time
	newest  time.Time
	lag     time.Duration
	lagAt   time.Time

	// now is the clock; nil means time.Now (test seam).
	now func() time.Time
}

func (t *SpoolTailer) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// Stats returns the counters from the tailer's most recent drain and the
// feed clock. Safe to call from another goroutine (the status probe) while
// the tailer polls.
func (t *SpoolTailer) Stats() SpoolStats {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	s := t.stats
	s.BytesLost = t.lost
	s.LostAt = t.lostAt
	s.NewestEvent = t.newest
	if !t.lagAt.IsZero() && t.clock().Sub(t.lagAt) <= spoolLagFresh {
		s.Lag = t.lag
	}
	return s
}

// recordFeedClock advances the feed clock to a drain's newest published
// event and measures how far the clock now trails the wall clock.
func (t *SpoolTailer) recordFeedClock(newest time.Time) {
	if newest.IsZero() {
		return
	}
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	if newest.After(t.newest) {
		t.newest = newest
	}
	t.lagAt = t.clock()
	t.lag = max(0, t.lagAt.Sub(t.newest))
}

// A full bus retains the next event on disk. Report its delivery delay even
// if no newer event was accepted; do not advance the published feed clock.
func (t *SpoolTailer) recordPendingLag(at time.Time) {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	t.lagAt = t.clock()
	t.lag = max(0, t.lagAt.Sub(at))
}

func (t *SpoolTailer) recordLost(bytes uint64) {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	t.lost += bytes
	t.lostAt = t.clock()
}

// recordDrain publishes one tick's counters. FloodSince starts on the first
// skipping tick and holds until a tick drains fully within budget.
func (t *SpoolTailer) recordDrain(s SpoolStats, skipped bool) {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	if skipped {
		if t.stats.FloodSince.IsZero() {
			s.FloodSince = time.Now()
		} else {
			s.FloodSince = t.stats.FloodSince
		}
	}
	t.stats = s
}

func NewSpoolTailer(b *bus.Bus) *SpoolTailer {
	return &SpoolTailer{bus: b, path: ESPoolPath}
}

// NewSpoolTailerAt exists for tests; production uses ESPoolPath.
func NewSpoolTailerAt(b *bus.Bus, path string) *SpoolTailer {
	return &SpoolTailer{bus: b, path: path}
}

func (t *SpoolTailer) Run(ctx context.Context) error {
	// The spool may appear a few seconds after the daemon starts (the
	// privileged collector is installed asynchronously); bounded wait, then
	// a permanent, actionable failure — retrying cannot conjure the file.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(t.path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return supervise.Permanent(fmt.Errorf(
				"privileged ES collector spool not present at %s — enable file telemetry in Settings", t.path))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return t.follow(ctx)
}

func (t *SpoolTailer) follow(ctx context.Context) error {
	var c spoolCursor
	for {
		c = t.poll(c)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// spoolCursor is the tail offset plus the spool's size and mtime as stat'ed
// before the drain that produced it, and the identity of the file the offset
// belongs to.
type spoolCursor struct {
	offset int64
	size   int64
	mod    time.Time
	file   os.FileInfo
}

// poll stats the spool and drains it only when its size or mtime changed
// since the last drain, or unread bytes remain (a rotation reset, a skipped
// line): an idle spool costs one stat per tick. A spool that is a different
// file than the cursor's was rotated: the rotated file (<path>.1) is read to
// its end from the cursor's offset first, then the new spool from its start.
func (t *SpoolTailer) poll(c spoolCursor) spoolCursor {
	st, err := os.Stat(t.path)
	if err != nil {
		return c // rotation window: the next tick finds both files
	}
	if c.file != nil && !os.SameFile(c.file, st) {
		if old, err := os.Stat(t.path + ".1"); err == nil && os.SameFile(old, c.file) {
			offset, file := t.drainOnce(t.path+".1", c.offset)
			if file == nil {
				return c // an unavailable retained file may be readable next tick
			}
			if offset < old.Size() && t.retained {
				// Finish retained events before starting the new file, including
				// when the consumer is still full on the next poll.
				return spoolCursor{offset: offset, size: old.Size(), mod: old.ModTime(), file: file}
			}
			if offset < old.Size() {
				t.recordLost(uint64(old.Size() - offset))
			}
		} else if c.offset < c.size {
			t.recordLost(uint64(c.size - c.offset))
		}
		c = spoolCursor{}
	} else if st.Size() < c.size && c.offset < c.size {
		t.recordLost(uint64(c.size - c.offset))
		c = spoolCursor{} // the replacement content starts at byte zero
	}
	if st.Size() == c.size && st.ModTime().Equal(c.mod) && c.offset >= c.size {
		return c
	}
	offset, file := t.drainOnce(t.path, c.offset)
	return spoolCursor{offset: offset, size: st.Size(), mod: st.ModTime(), file: file}
}

// drainOnce reads complete lines of path past `offset`, publishing each as
// an event. Returns the offset to resume from and the identity of the file
// it read (nil when it could not open it). A file smaller than offset
// (truncated in place) or unreadable → reset/wait, never error the
// supervisor: the spool is a best-effort handoff and the collector rewrites
// it within seconds.
func (t *SpoolTailer) drainOnce(path string, offset int64) (int64, os.FileInfo) {
	t.retained = false
	open := t.open
	if open == nil {
		open = os.Open
	}
	f, err := open(path)
	if err != nil {
		return 0, nil // rotation window: restart from 0 next tick
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return offset, nil
	}
	if st.Size() < offset {
		return 0, st // truncated: read the file from its start
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return offset, st
	}

	unread := st.Size() - offset
	overBudget := unread > spoolDrainBudget

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	scanner.Split(scanCompleteLines)
	var lastGood int64
	var linesThisTick, parsedThisTick uint64
	var newest time.Time
	published := false
	budgetHit := false
	for scanner.Scan() {
		line := scanner.Bytes()
		linesThisTick++
		switch e, v := parseESLine(line); v {
		case esEvent:
			parsedThisTick++
			if !t.bus.TryPublish(e) {
				t.retained = true
				// Leave this complete line in the spool for the next poll. The
				// privileged writer and other collectors remain non-blocking.
				t.recordFeedClock(newest)
				t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick}, false)
				t.recordPendingLag(e.TS)
				if published && t.OnProduce != nil {
					t.OnProduce()
				}
				return offset + lastGood, st
			}
			published = true
			if e.TS.After(newest) {
				newest = e.TS
			}
		case esOwn:
			parsedThisTick++ // the daemon's own file activity: valid, not an event
		}
		lastGood += int64(len(line)) + 1
		if overBudget && lastGood >= spoolDrainBudget {
			budgetHit = true
			break
		}
	}
	t.recordFeedClock(newest)
	if published && t.OnProduce != nil {
		t.OnProduce()
	}
	// An oversized line (>1MB, a corrupt spool write) errors the scanner
	// and would otherwise leave the offset frozen on it forever — every
	// poll retries the same giant line. Skip past it: the tail resumes on
	// the next tick. lastGood only counts complete lines, so finding the
	// next newline past the current position recovers cleanly.
	if err := scanner.Err(); err != nil {
		if info, statErr := f.Stat(); statErr == nil {
			if rest := info.Size() - offset - lastGood; rest > 0 {
				// Skip the stuck line plus its terminator.
				if skip := rest; skip > 8<<20 {
					resume := offset + lastGood + skip // giant garbage: drop it all
					t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick, Skipped: 1, BytesSkipped: uint64(skip)}, false)
					return resume, st
				}
				skipBuf := make([]byte, 64*1024)
				for rest := info.Size() - offset - lastGood; rest > 0; {
					n := int64(len(skipBuf))
					if rest < n {
						n = rest
					}
					read, _ := f.ReadAt(skipBuf, offset+lastGood)
					if read <= 0 {
						break
					}
					if i := indexByte(skipBuf[:read], '\n'); i >= 0 {
						resume := offset + lastGood + int64(i) + 1
						t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick}, false)
						return resume, st
					}
					rest -= int64(read)
					lastGood += int64(read)
				}
				t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick}, false)
				return offset + lastGood, st
			}
		}
		log.Printf("collect: spool scanner error at offset %d: %v", offset+lastGood, err)
	}

	resume := offset + lastGood
	if budgetHit {
		if parsedThisTick > 0 {
			t.retained = true
			// A valid burst is durable backlog, not malformed input. Bound
			// parsing work per poll without skipping the remaining evidence.
			t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick}, false)
			return resume, st
		}
		// The unread tail exceeded the budget and the scan loop cut off
		// mid-tail (not on a parse error): the rest is skipped in bulk —
		// counted by newline, never handed to the scanner or the parser.
		skipTo, skippedLines, skippedBytes := skipTail(f, resume, st.Size())
		t.recordLost(skippedBytes)
		t.recordDrain(SpoolStats{
			Lines:        linesThisTick,
			Parsed:       parsedThisTick,
			Skipped:      skippedLines,
			BytesSkipped: skippedBytes,
		}, true)
		return skipTo, st
	}
	t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick}, false)
	return resume, st
}

// scanCompleteLines is bufio.ScanLines without its last-line rule: a line
// the writer has not finished (no newline yet) is left unread until it is,
// instead of being taken as a complete line and its rest as garbage.
func scanCompleteLines(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	return 0, nil, nil
}

// skipTail counts complete lines and bytes from `from` to `to` without
// parsing them, reading in fixed chunks so an arbitrarily large tail costs
// O(bytes) newline-scanning, not a scanner token per line. It returns the
// offset to resume from: `to` when the tail ends on a newline, otherwise the
// last newline before `to` — a still-being-written partial line is left for
// the next tick to complete.
func skipTail(f *os.File, from, to int64) (resume int64, lines, bytesSkipped uint64) {
	if to <= from {
		return from, 0, 0
	}
	buf := make([]byte, 64*1024)
	lastNL := from
	pos := from
	for pos < to {
		n := int64(len(buf))
		if rem := to - pos; rem < n {
			n = rem
		}
		read, err := f.ReadAt(buf[:n], pos)
		if read <= 0 {
			break
		}
		chunk := buf[:read]
		lines += uint64(bytes.Count(chunk, []byte{'\n'}))
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			lastNL = pos + int64(i) + 1
		}
		pos += int64(read)
		if err != nil {
			break
		}
	}
	return lastNL, lines, uint64(lastNL - from)
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
