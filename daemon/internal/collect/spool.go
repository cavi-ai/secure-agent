package collect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// The privileged ES collector's spool (secure-agentd --es-collector writes it as root).
const ESPoolPath = "/var/db/secure-agent/es-spool.jsonl"

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
	for scanner.Scan() {
		line := scanner.Bytes()
		if e, ok := ParseESLine(line); ok {
			t.bus.Publish(e)
		}
		lastGood += int64(len(line)) + 1
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
