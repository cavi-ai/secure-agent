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
// parse in one tick. A defective privileged writer can grow the spool tens
// of MB in seconds with near-empty garbage lines: without a budget, every
// tick pays bufio.Scanner + the parser over the whole flood (measured: 19%
// cum CPU in drainOnce, 6% in encoding/json.checkValid, on a spool that grew
// 24.8 MB in 5s and never parsed a line). Past the budget the rest of the
// tail is skipped in bulk — counted, never scanned line by line.
const spoolDrainBudget = 4 << 20 // 4 MiB

// SpoolStats are the tailer's counters from its most recent drain: how many
// lines it saw, how many parsed, how many it skipped past the per-tick
// budget without attempting to parse, and how many bytes that was.
// FloodSince is zero unless the tailer is currently having to skip; it is
// set the first tick that skips and cleared the first tick that drains
// fully within budget.
type SpoolStats struct {
	Lines        uint64
	Parsed       uint64
	Skipped      uint64
	BytesSkipped uint64
	FloodSince   time.Time
}

// The privileged ES collector's spool (the collector daemon writes it as root).
const ESPoolPath = "/var/db/secure-agent/es-spool.jsonl"

// ESServiceLabel is the root LaunchDaemon label running the privileged
// collector. The user daemon probes its real launchd state so posture can
// say "the root service is crash-looping" — the tailer being alive proves
// nothing about the writer.
const ESServiceLabel = "com.cavi-ai.secure-agent-esd"

// SpoolAvailable reports whether the privileged ES collector's spool exists
// and is readable by this (unprivileged) daemon — the signal that file
// telemetry should come from the spool tail instead of a direct eslogger
// child (which macOS only permits as root).
func SpoolAvailable() bool {
	f, err := os.Open(ESPoolPath)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// ESServiceSnapshot is one probe of the privileged collector's real state:
// the launchd service state string, the spool's size and mtime, and the
// mtime of the program launchd runs for it (zero when absent). The probe is injectable
// (ESServiceProbe) so tests never shell out.
type ESServiceSnapshot struct {
	State       string    `json:"state"`
	SpoolSize   int64     `json:"spool_size"`
	SpoolMtime  time.Time `json:"spool_mtime"`
	HelperMtime time.Time `json:"helper_mtime"`

	// Flooding and UnparsedShare come from the tailer's drain stats (nil
	// when the daemon does not tail a spool): Flooding is true while the
	// tailer is having to skip past its per-tick budget; UnparsedShare is
	// the fraction of lines in the last drain that did not parse.
	// BytesSkipped is how many tail bytes the last drain skipped in bulk.
	Flooding      bool    `json:"flooding"`
	UnparsedShare float64 `json:"unparsed_share"`
	BytesSkipped  uint64  `json:"bytes_skipped"`
}

// SpoolState renders the spool facts for humans ("3.2 MB, updated 12 min ago").
func (s ESServiceSnapshot) SpoolState() string {
	if s.SpoolSize == 0 && s.SpoolMtime.IsZero() {
		return "absent"
	}
	return fmt.Sprintf("%d bytes, updated %s ago", s.SpoolSize, time.Since(s.SpoolMtime).Round(time.Second))
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
	if st, serr := os.Stat(ESPoolPath); serr == nil {
		s.SpoolSize, s.SpoolMtime = st.Size(), st.ModTime()
	}
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

	// OnProduce, when set, is called after any spool event is published —
	// the supervisor's coverage heartbeat: a tailer whose spool stopped
	// growing must not read as healthy coverage.
	OnProduce func()

	statsMu sync.Mutex
	stats   SpoolStats
}

// Stats returns the counters from the tailer's most recent drain. Safe to
// call from another goroutine (the status probe) while the tailer polls.
func (t *SpoolTailer) Stats() SpoolStats {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	return t.stats
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
// before the drain that produced it.
type spoolCursor struct {
	offset int64
	size   int64
	mod    time.Time
}

// poll stats the spool and drains it only when its size or mtime changed
// since the last drain, or unread bytes remain (a rotation reset, a skipped
// line): an idle spool costs one stat per tick.
func (t *SpoolTailer) poll(c spoolCursor) spoolCursor {
	st, err := os.Stat(t.path)
	if err != nil {
		return spoolCursor{} // rotation window: restart from 0 next tick
	}
	if st.Size() == c.size && st.ModTime().Equal(c.mod) && c.offset >= c.size {
		return c
	}
	return spoolCursor{offset: t.drainOnce(c.offset), size: st.Size(), mod: st.ModTime()}
}

// drainOnce reads complete lines past `offset`, publishing each as an event.
// Returns the offset to resume from. File smaller than offset (rotation) or
// unreadable → reset/wait, never error the supervisor: the spool is a
// best-effort handoff and the collector rewrites it within seconds.
func (t *SpoolTailer) drainOnce(offset int64) int64 {
	open := t.open
	if open == nil {
		open = os.Open
	}
	f, err := open(t.path)
	if err != nil {
		return 0 // rotation window: restart from 0 next tick
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return offset
	}
	if st.Size() < offset {
		return 0 // rotated/truncated: read the new file from its start
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}

	unread := st.Size() - offset
	overBudget := unread > spoolDrainBudget

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lastGood int64
	var linesThisTick, parsedThisTick uint64
	published := false
	budgetHit := false
	for scanner.Scan() {
		line := scanner.Bytes()
		linesThisTick++
		if e, ok := ParseESLine(line); ok {
			t.bus.Publish(e)
			published = true
			parsedThisTick++
		}
		lastGood += int64(len(line)) + 1
		if overBudget && lastGood >= spoolDrainBudget {
			budgetHit = true
			break
		}
	}
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
					return resume
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
						return resume
					}
					rest -= int64(read)
					lastGood += int64(read)
				}
				t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick}, false)
				return offset + lastGood
			}
		}
		log.Printf("collect: spool scanner error at offset %d: %v", offset+lastGood, err)
	}

	resume := offset + lastGood
	if budgetHit {
		// The unread tail exceeded the budget and the scan loop cut off
		// mid-tail (not on a parse error): the rest is skipped in bulk —
		// counted by newline, never handed to the scanner or the parser.
		skipTo, skippedLines, skippedBytes := skipTail(f, resume, st.Size())
		t.recordDrain(SpoolStats{
			Lines:        linesThisTick + skippedLines,
			Parsed:       parsedThisTick,
			Skipped:      skippedLines,
			BytesSkipped: skippedBytes,
		}, true)
		return skipTo
	}
	t.recordDrain(SpoolStats{Lines: linesThisTick, Parsed: parsedThisTick}, false)
	return resume
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
