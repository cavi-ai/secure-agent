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
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
)

const (
	esSpoolDir = "/var/db/secure-agent"
	// 32MB handoff buffer: the user daemon drains continuously; rotation
	// prevents unbounded root-written growth on pathological activity.
	maxSpoolBytes = 32 << 20
)

// runESCollector never returns except on fatal setup error.
func runESCollector() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (Endpoint Security requires it)")
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

// spoolWriter serializes appends with size-capped rotation.
type spoolWriter struct {
	mu   sync.Mutex
	f    *os.File
	size int64
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
	if err := w.rotateLocked(); err != nil {
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
