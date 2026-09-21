package main

// The privileged ES-collector mode: this binary runs as root under launchd,
// spawning Apple's eslogger and appending its JSON to the spool the
// unprivileged daemon tails. It deliberately touches NOTHING else — no
// store, no socket, no API — so the root surface is exactly "run eslogger,
// append to /var/db/secure-agent/es-spool.jsonl".
//
// Why this binary instead of a separate helper: the operator has ALREADY
// granted Full Disk Access to secure-agentd (the daemon path they dragged
// into Settings). TCC attributes the grant to this binary, so when THIS
// process creates the Endpoint Security client, macOS permits it without
// any additional drag — the whole UX becomes one FDA grant.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	esSpoolDir = "/var/db/secure-agent"
	// esStateDir holds the integrity hash. It must NOT be the spool dir:
	// the spool dir is chowned to the console user (so the unprivileged
	// daemon can read the spool), and a hash file in a user-owned directory
	// can be swapped out from under the check.
	esStateDir = "/Library/Application Support/secure-agent"
	// 32MB handoff buffer: the user daemon drains continuously; rotation
	// prevents unbounded root-written growth on pathological activity.
	maxSpoolBytes = 32 << 20
	// esRetryInterval backs off between eslogger respawns inside this
	// process when the failure is the expected pre-grant one (no ES
	// permission yet). Internal retry keeps the service state "running"
	// instead of crash-looping through launchd on every denied attempt.
	esRetryInterval = 60 * time.Second
)

// verifyOwnIntegrity refuses to run as root from a binary the login user (or
// any admin) could have swapped since install. The LaunchDaemon executes this
// binary as root; a writable binary converts "monitoring tool" into
// "root on request". The binary's own SHA-256 is recorded in
// /Library/Application Support/secure-agent/esd.binhash at install time (a
// root-owned directory, written by the privileged install step — NOT the
// spool dir, which is chowned to the console user); on every start the
// running file must still match. A missing hash file is treated as
// unverified: the installer always writes one, so its absence means tampering
// or a stale install — both fail closed.
func verifyOwnIntegrity() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self: %w", err)
	}
	real, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = real
	}
	info, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("stat self: %w", err)
	}
	// Mode AND ownership are the cheap half: a 0755 binary owned by the
	// login user is exactly as swappable as a writable one. Refuse anything
	// not owned by root with no group/world write bits.
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing: %s is group/world-writable (perms %#o)", exe, info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return fmt.Errorf("refusing: %s is not owned by root", exe)
	}
	hashPath := filepath.Join(esStateDir, "esd.binhash")
	want, err := os.ReadFile(hashPath)
	if err != nil {
		return fmt.Errorf("refusing: integrity hash %s unreadable (stale or tampered install): %w", hashPath, err)
	}
	got, err := fileSHA256(exe)
	if err != nil {
		return fmt.Errorf("hash self: %w", err)
	}
	if got != string(want) {
		return fmt.Errorf("refusing: %s changed since install (hash mismatch)", exe)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 256*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, err := h.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if err != nil {
			if err.Error() == "EOF" {
				return hex.EncodeToString(h.Sum(nil)), nil
			}
			return "", err
		}
	}
}

// runESCollector never returns except on fatal setup error.
func runESCollector() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (Endpoint Security requires it)")
	}
	// Fail closed on a binary the login user could have replaced. This runs
	// BEFORE anything else touches the spool or eslogger.
	if err := verifyOwnIntegrity(); err != nil {
		return err
	}
	if _, err := exec.LookPath("eslogger"); err != nil {
		return fmt.Errorf("eslogger not found: %w", err)
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
	f    *os.File
	size int64
}

// open attaches to the existing spool, resuming after whatever bytes are
// already there. Existing content is preserved — unread events are the
// tailer's data, not garbage.
func (w *spoolWriter) open() error {
	f, err := os.OpenFile(collect.ESPoolPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("open spool: %w", err)
	}
	if err := chownSpoolFileToConsoleUser(collect.ESPoolPath); err != nil {
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
	_ = os.Remove(collect.ESPoolPath + ".1")
	_ = os.Rename(collect.ESPoolPath, collect.ESPoolPath+".1")
	_ = chownSpoolFileToConsoleUser(collect.ESPoolPath + ".1")
	f, err := os.OpenFile(collect.ESPoolPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("reopen spool: %w", err)
	}
	if err := chownSpoolFileToConsoleUser(collect.ESPoolPath); err != nil {
		return err
	}
	w.f = f
	w.size = 0
	return nil
}

func pumpToSpool(stdout interface{ Read([]byte) (int, error) }) error {
	w := &spoolWriter{}
	// Open WITHOUT rotating: the spool may hold events the tailer has not
	// drained yet (this process may have crash-looped; destroying unread
	// data on every respawn loses evidence). Rotation happens on
	// size only, inside writeLine.
	if err := w.open(); err != nil {
		return err
	}
	buf := make([]byte, 0, 256*1024)
	tmp := make([]byte, 64*1024)
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
				line := buf[:nl]
				buf = append(buf[:0], buf[nl+1:]...)
				if err := w.writeLine(line); err != nil {
					return fmt.Errorf("spool write: %w", err)
				}
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
