package main

// The privileged ES-collector mode: runs as root under launchd (the app
// registers it with SMAppService.daemon from its bundle), spawns eslogger,
// appends its JSON to the spool the unprivileged daemon tails. Touches
// nothing else: no store, no socket, no API.
//
// TCC attributes the ES grant to the app bundle that ships this binary, so
// the operator's one Full Disk Access grant for the app covers the chain.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
)

const (
	// esCollectorName is the executable name the app bundle gives this
	// binary for the collector daemon; running under it selects the mode.
	esCollectorName = "secure-agent-esd"
	esSpoolDir      = "/var/db/secure-agent"
	// 32MB handoff buffer: the user daemon drains continuously; rotation
	// prevents unbounded root-written growth on pathological activity.
	maxSpoolBytes = 32 << 20
	// esRetryInterval backs off between eslogger respawns inside this
	// process when the failure is the expected pre-grant one (no ES
	// permission yet). Internal retry keeps the service state "running"
	// instead of crash-looping through launchd on every denied attempt.
	esRetryInterval = 60 * time.Second
)

// errESPermanent marks failures that cannot clear on their own (wrong user,
// integrity refusal, eslogger missing): the process must exit 0 so launchd
// leaves the service stopped instead of respawning it forever.
var errESPermanent = errors.New("permanent es-collector failure")

func permanent(err error) error { return fmt.Errorf("%w: %v", errESPermanent, err) }

// IsESPermanentFailure reports whether err is a permanent refusal (the
// caller exits 0 for those).
func IsESPermanentFailure(err error) bool { return errors.Is(err, errESPermanent) }

// isESCollectorInvocation reports whether this process runs the ES
// collector: launched under the in-bundle collector name, or with
// --es-collector (the flag older LaunchDaemon plists pass).
func isESCollectorInvocation(argv0 string, flag bool) bool {
	return flag || filepath.Base(argv0) == esCollectorName
}

// codesignVerify checks path's code signature; tests replace it.
var codesignVerify = func(path string) error {
	out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, oneLine(string(out)))
	}
	return nil
}

// verifyOwnIntegrity refuses to run as root from a binary that is
// group/world-writable or whose code signature no longer verifies. The
// binary lives in the app bundle, which SMAppService validates against the
// app's signature at registration; a modified file breaks that signature.
func verifyOwnIntegrity() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self: %w", err)
	}
	real, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = real
	}
	return verifyExecutable(exe)
}

func verifyExecutable(exe string) error {
	info, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("stat self: %w", err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing: %s is group/world-writable (perms %#o)", exe, info.Mode().Perm())
	}
	if err := codesignVerify(exe); err != nil {
		return fmt.Errorf("refusing: %s fails code signature verification: %w", exe, err)
	}
	return nil
}

// runESCollector never returns except on fatal setup error.
func runESCollector() error {
	if os.Geteuid() != 0 {
		return permanent(fmt.Errorf("must run as root (Endpoint Security requires it)"))
	}
	// Fail closed on a modified or writable binary. This runs BEFORE
	// anything else touches the spool or eslogger.
	if err := verifyOwnIntegrity(); err != nil {
		return permanent(err)
	}
	if _, err := exec.LookPath("eslogger"); err != nil {
		return permanent(fmt.Errorf("eslogger not found: %w", err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(esSpoolDir, 0o750); err != nil {
		return fmt.Errorf("spool dir: %w", err)
	}
	if err := chownSpoolToConsoleUser(); err != nil {
		log.Printf("es-collector: chown spool (daemon may not read it): %v", err)
	}

	for {
		err := runESLoggerOnce(ctx)
		if ctx.Err() != nil {
			return nil // shutdown: eslogger was killed by the context
		}
		if err == nil {
			return nil
		}
		if !isESPermissionFailure(err) {
			return err
		}
		// The ES client is denied until the operator grants eslogger its
		// permission in Settings. That is the EXPECTED pre-grant state, so
		// wait and retry inside this process: exiting nonzero would let
		// launchd respawn-churn the service on every denied attempt.
		log.Printf("es-collector: %v — waiting %s for the eslogger permission grant", err, esRetryInterval)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(esRetryInterval):
		}
	}
}

// runESLoggerOnce runs eslogger to completion (or ctx cancellation) and
// pumps its JSON to the spool.
func runESLoggerOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "eslogger", "open", "exec", "unlink", "rename", "tcc_modify", "--format", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("eslogger stdout pipe: %w", err)
	}
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start eslogger: %w", err)
	}
	log.Printf("es-collector: eslogger started (pid %d), spool %s", cmd.Process.Pid, collect.ESPoolPath)

	writeErr := pumpToSpool(stdout)
	_ = cmd.Process.Kill()
	waitErr := cmd.Wait()
	if writeErr != nil {
		return fmt.Errorf("spool write: %w", writeErr)
	}
	if waitErr != nil {
		return fmt.Errorf("eslogger exited: %w (stderr: %s)", waitErr, oneLine(stderr.String()))
	}
	return nil
}

// isESPermissionFailure reports whether an eslogger failure is the expected
// "no ES client permission yet" denial rather than a real crash.
func isESPermissionFailure(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not permitted")
}

// spoolWriter serializes appends with size-capped rotation.
type spoolWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// open attaches to the existing spool, resuming after whatever bytes are
// already there. Existing content is preserved — unread events are the
// tailer's data, not garbage.
func (w *spoolWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("open spool: %w", err)
	}
	if err := chownSpoolFileToConsoleUser(w.path); err != nil {
		log.Printf("es-collector: chown spool (daemon may not read it): %v", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat spool: %w", err)
	}
	w.f = f
	w.size = info.Size()
	return nil
}

func (w *spoolWriter) writeLine(line []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size > maxSpoolBytes {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := w.f.Write(append(line, '\n'))
	if err != nil {
		return err
	}
	w.size += int64(n)
	return nil
}

func (w *spoolWriter) rotateLocked() error {
	if w.f != nil {
		_ = w.f.Close()
	}
	_ = os.Remove(w.path + ".1")
	_ = os.Rename(w.path, w.path+".1")
	_ = chownSpoolFileToConsoleUser(w.path + ".1")
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("reopen spool: %w", err)
	}
	if err := chownSpoolFileToConsoleUser(w.path); err != nil {
		return err
	}
	w.f = f
	w.size = 0
	return nil
}

func pumpToSpool(stdout interface{ Read([]byte) (int, error) }) error {
	return pumpToSpoolAt(stdout, collect.ESPoolPath)
}

// pumpToSpoolAt copies newline-delimited records from stdout to the spool
// at path, skipping empty lines and the lines keepESLine drops; the drop
// count goes to the log once a minute.
func pumpToSpoolAt(stdout interface{ Read([]byte) (int, error) }, path string) error {
	w := &spoolWriter{path: path}
	// Open WITHOUT rotating: the spool may hold events the tailer has not
	// drained yet (this process may have crash-looped; destroying unread
	// data on every respawn loses evidence). Rotation happens on
	// size only, inside writeLine.
	if err := w.open(); err != nil {
		return err
	}
	buf := make([]byte, 0, 256*1024)
	tmp := make([]byte, 64*1024)
	var stats esFilterStats
	for {
		n, err := stdout.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				nl := indexOfByte(buf, '\n')
				if nl < 0 {
					if len(buf) > 4<<20 {
						buf = buf[:0]
					}
					break
				}
				// line aliases buf, so it is written before buf is compacted.
				line := buf[:nl]
				if len(bytes.TrimSpace(line)) > 0 { // empty lines are skipped
					if keepESLine(line) {
						if err := w.writeLine(line); err != nil {
							return fmt.Errorf("spool write: %w", err)
						}
						stats.kept++
					} else {
						stats.dropped++
					}
					if msg, ok := stats.report(time.Now()); ok {
						log.Print(msg)
					}
				}
				buf = append(buf[:0], buf[nl+1:]...)
			}
		}
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return fmt.Errorf("eslogger read: %w", err)
		}
	}
}

func indexOfByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func oneLine(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// chownSpoolToConsoleUser gives the spool to the console user so the
// unprivileged daemon can read it; world stays unreadable. Paths only.
func chownSpoolToConsoleUser() error {
	uid, err := consoleUserUID()
	if err != nil {
		return err
	}
	return os.Chown(esSpoolDir, uid, -1)
}

func chownSpoolFileToConsoleUser(path string) error {
	uid, err := consoleUserUID()
	if err != nil {
		return err
	}
	return os.Chown(path, uid, -1)
}

func consoleUserUID() (int, error) {
	out, err := exec.Command("/usr/bin/stat", "-f", "%u", "/dev/console").Output()
	if err != nil {
		return 0, err
	}
	var uid int
	if _, err := fmt.Sscanf(string(out), "%d", &uid); err != nil {
		return 0, err
	}
	return uid, nil
}

type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > 64*1024 {
		b.buf = b.buf[len(b.buf)-32*1024:]
	}
	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
