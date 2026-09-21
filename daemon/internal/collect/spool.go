package collect

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// The privileged ES collector's spool (secure-agentd --es-collector writes it as root).
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
// the launchd service state string plus the spool's size and mtime. The
// probe is injectable (ESServiceProbe) so tests never shell out.
type ESServiceSnapshot struct {
	State      string    `json:"state"`
	SpoolSize  int64     `json:"spool_size"`
	SpoolMtime time.Time `json:"spool_mtime"`
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
// an unprivileged daemon can: stat the spool (size + mtime) and read the
// launchd service state via launchctl print. Spawning/exit != 0 with a
// stale spool is the crash-loop signature (rapid respawns while the tailer
// reports running).
func ESServiceState() (string, int64, time.Time, error) {
	var size int64
	var mtime time.Time
	if st, serr := os.Stat(ESPoolPath); serr == nil {
		size, mtime = st.Size(), st.ModTime()
	}
	out, cerr := exec.Command("/bin/launchctl", "print", "system/"+ESServiceLabel).Output()
	if cerr != nil {
		// Not loaded / not running as root: report the spool facts anyway.
		return "not-loaded", size, mtime, nil
	}
	return parseLaunchctlState(string(out)), size, mtime, nil
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
// Poll-reopen model (simple, rotation-proof): every 200ms, open the file,
// skip to the last-read offset, emit new lines, remember the offset. A
// rotated/truncated/missing file resets the offset to "read what exists
// now". At 200ms granularity the latency cost is negligible next to the
// correlator's own windows.
type SpoolTailer struct {
	bus  *bus.Bus
	path string

	// OnProduce, when set, is called after any spool event is published —
	// the supervisor's coverage heartbeat: a tailer whose spool stopped
	// growing must not read as healthy coverage.
	OnProduce func()
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
				"privileged ES collector spool not present at %s — install it from Settings (admin prompt)", t.path))
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
	var offset int64
	for {
		offset = t.drainOnce(offset)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// drainOnce reads complete lines past `offset`, publishing each as an event.
// Returns the offset to resume from. File smaller than offset (rotation) or
// unreadable → reset/wait, never error the supervisor: the spool is a
// best-effort handoff and the collector rewrites it within seconds.
func (t *SpoolTailer) drainOnce(offset int64) int64 {
	f, err := os.Open(t.path)
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

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lastGood int64
	published := false
	for scanner.Scan() {
		line := scanner.Bytes()
		if e, ok := ParseESLine(line); ok {
			t.bus.Publish(e)
			published = true
		}
		lastGood += int64(len(line)) + 1
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
					return offset + lastGood + skip // giant garbage: drop it all
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
						return offset + lastGood + int64(i) + 1
					}
					rest -= int64(read)
					lastGood += int64(read)
				}
				return offset + lastGood
			}
		}
		log.Printf("collect: spool scanner error at offset %d: %v", offset+lastGood, err)
	}
	return offset + lastGood
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
