package main

// The privileged ES-collector mode: runs as root under launchd (the app
// registers it with SMAppService.daemon from its bundle), spawns eslogger,
// appends its JSON to the spool the unprivileged daemon tails. Touches
// nothing else: no store, no socket, no API.
//
// TCC attributes the ES grant to the app bundle that ships this binary, so
// the operator's one Full Disk Access grant for the app covers the chain.
import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
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
	// esMaxLine bounds one eslogger line held in memory; a longer one is
	// discarded through its newline.
	esMaxLine = 4 << 20
	// esRetryInterval backs off between eslogger respawns inside this
	// process when the failure is the expected pre-grant one (no ES
	// permission yet). Internal retry keeps the service state "running"
	// instead of crash-looping through launchd on every denied attempt.
	esRetryInterval = 60 * time.Second
	// esMaxLag is how far eslogger's newest event may trail the clock before
	// the collector restarts it. eslogger holds every event it has not yet
	// written in its own memory: under a flood of opens it falls behind, the
	// queue grows by gigabytes, memory pressure slows it further, and it
	// never catches up. Restarting drops that queue; its events are already
	// too late for a flag or a resource episode.
	esMaxLag = 60 * time.Second
	// esLagConfirm is how long the lag must stay over esMaxLag: records held
	// in the pipe across a sleep read stale once on wake, then fresh.
	esLagConfirm = 30 * time.Second
	// esLagCheckInterval spaces the lag checks: one timestamp read per
	// interval, not per line.
	esLagCheckInterval = time.Second
)

// esMaxRSS caps eslogger's resident memory. Events it cannot write out as fast
// as they arrive wait there; past the cap the collector restarts it, as it
// does one that trails the clock. Its working set otherwise stays near 50 MB.
var (
	esMaxRSS           uint64 = 256 << 20
	esRSSCheckInterval        = 2 * time.Second
)

// errESBehind marks an eslogger the collector stopped for falling behind.
var errESBehind = errors.New("eslogger fell behind")

// errESReplaced marks a collector whose executable was replaced on disk after
// it started. TCC refuses new ES clients to the stale process, so it exits
// nonzero and launchd starts the job again from the new binary.
var errESReplaced = errors.New("es-collector executable replaced since start")

// esNow is the collector's clock; tests replace it.
var esNow = time.Now

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

// startedExecutable resolves and stats this process's executable, so the
// file info names the binary that was exec'd.
func startedExecutable() (string, os.FileInfo, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", nil, fmt.Errorf("resolve self: %w", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	info, err := os.Stat(exe)
	if err != nil {
		return "", nil, fmt.Errorf("stat self: %w", err)
	}
	return exe, info, nil
}

// executableReplaced reports whether exe is no longer the file described by
// started: an app update swaps the bundle under the running collector.
func executableReplaced(exe string, started os.FileInfo) bool {
	now, err := os.Stat(exe)
	if err != nil {
		return true
	}
	return !os.SameFile(started, now) || !now.ModTime().Equal(started.ModTime()) || now.Size() != started.Size()
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
	exe, started, err := startedExecutable()
	if err != nil {
		return permanent(err)
	}
	// Fail closed on a modified or writable binary. This runs BEFORE
	// anything else touches the spool or eslogger.
	if err := verifyOwnIntegrity(); err != nil {
		return permanent(err)
	}
	// The bundle runs this collector from Contents/MacOS and the user daemon
	// from Contents/Helpers.
	setESDaemonExe(filepath.Join(filepath.Dir(filepath.Dir(exe)), "Helpers", "secure-agentd"))
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
	health := newESCollectorHealth(collect.ESCollectorStatusPath, os.Getpid(), 30*time.Second)
	defer health.Close()

	return superviseESLogger(ctx,
		func() error { return runESLoggerOnce(ctx, health) },
		func() bool { return executableReplaced(exe, started) })
}

// superviseESLogger runs eslogger until shutdown or a clean exit: it restarts
// one that fell behind and retries a denied one every esRetryInterval. Once
// replaced reports a new binary on disk it returns errESReplaced instead.
func superviseESLogger(ctx context.Context, runOnce func() error, replaced func() bool) error {
	for {
		err := runOnce()
		if ctx.Err() != nil {
			return nil // shutdown: eslogger was killed by the context
		}
		if err == nil {
			return nil
		}
		if replaced() {
			return fmt.Errorf("%w: %v", errESReplaced, err)
		}
		if errors.Is(err, errESBehind) {
			log.Printf("es-collector: %v — restarting eslogger and dropping the events it still held", err)
			continue
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

// esLoggerEvents are the ES events the helper subscribes to. tcc_modify
// needs macOS 15.4, which already offers every system-change event here
// (BTM and XProtect 13.0, profile_add 14.0, gatekeeper_user_override 15.0).
var esLoggerEvents = []string{
	"open", "exec", "unlink", "rename", "create", "tcc_modify",
	"btm_launch_item_add", "btm_launch_item_remove", "xp_malware_detected",
	"profile_add", "gatekeeper_user_override",
}

// runESLoggerOnce runs eslogger to completion (or ctx cancellation) and
// pumps its JSON to the spool.
func runESLoggerOnce(ctx context.Context, health *esCollectorHealth) error {
	cmd := exec.CommandContext(ctx, "eslogger", append(esLoggerEvents, "--format", "json")...)
	return runESLoggerCommand(ctx, cmd, health, collect.ESPoolPath)
}

func runESLoggerCommand(ctx context.Context, cmd *exec.Cmd, health *esCollectorHealth, spoolPath string) (result error) {
	health.setState("starting")
	defer func() {
		state := "failed"
		switch {
		case ctx.Err() != nil || result == nil:
			state = "stopped"
		case isESPermissionFailure(result):
			state = "permission_denied"
		case errors.Is(result, errESBehind):
			state = "restarting"
		}
		health.setState(state)
	}()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("eslogger stdout pipe: %w", err)
	}
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start eslogger: %w", err)
	}
	log.Printf("es-collector: eslogger started (pid %d), spool %s", cmd.Process.Pid, spoolPath)

	stopWatch := watchESLoggerMemory(cmd.Process)
	writeErr := pumpToSpoolObserved(stdout, spoolPath, health.delivered)
	_ = cmd.Process.Kill()
	waitErr := cmd.Wait()
	if overErr := stopWatch(); overErr != nil {
		return overErr
	}
	if errors.Is(writeErr, errESBehind) {
		return writeErr
	}
	if writeErr != nil {
		return fmt.Errorf("spool write: %w", writeErr)
	}
	if waitErr != nil {
		return fmt.Errorf("eslogger exited: %w (stderr: %s)", waitErr, oneLine(stderr.String()))
	}
	return nil
}

// watchESLoggerMemory kills p once its resident memory passes esMaxRSS. stop
// ends the watch and returns the overrun as errESBehind, or nil.
func watchESLoggerMemory(p *os.Process) (stop func() error) {
	quit := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		tick := time.NewTicker(esRSSCheckInterval)
		defer tick.Stop()
		for {
			select {
			case <-quit:
				result <- nil
				return
			case <-tick.C:
				info, ok := agents.NewProcSource().Info(int32(p.Pid))
				if ok && info.RSSBytes > esMaxRSS {
					_ = p.Kill()
					result <- fmt.Errorf("%w: it holds %d MB of events it has not written, over the %d MB cap",
						errESBehind, info.RSSBytes>>20, esMaxRSS>>20)
					return
				}
			}
		}
	}()
	return func() error {
		close(quit)
		return <-result
	}
}

// isESPermissionFailure reports whether an eslogger failure is the expected
// "no ES client permission yet" denial rather than a real crash.
func isESPermissionFailure(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "es_new_client_result_err_not_permitted") || strings.Contains(message, "responsible process needs tcc full disk access authorization")
}

// spoolWriter serializes appends with size-capped rotation. Lines are
// buffered and reach the file on flush, once per read of eslogger's output,
// not one write per line.
type spoolWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
	bw   *bufio.Writer
	size int64 // bytes in the file and the buffer
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
	w.bw = bufio.NewWriterSize(f, spoolBufferBytes)
	w.size = info.Size()
	return nil
}

// spoolBufferBytes holds one read of eslogger's output, compacted.
const spoolBufferBytes = 64 << 10

func (w *spoolWriter) writeLine(line []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size > maxSpoolBytes {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := w.bw.Write(line)
	if err == nil {
		err = w.bw.WriteByte('\n')
		n++
	}
	if err != nil {
		return err
	}
	w.size += int64(n)
	return nil
}

// flush writes the buffered lines to the spool.
func (w *spoolWriter) flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.bw == nil {
		return nil
	}
	return w.bw.Flush()
}

func (w *spoolWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		_ = w.bw.Flush()
		_ = w.f.Close()
		w.f, w.bw = nil, nil
	}
}

func (w *spoolWriter) rotateLocked() error {
	if w.f != nil {
		if err := w.bw.Flush(); err != nil {
			return err
		}
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
	w.bw.Reset(f)
	w.size = 0
	return nil
}

// pumpToSpoolAt copies newline-delimited records from stdout to the spool
// at path, skipping empty lines and the lines keepESLine drops and writing
// each kept line reduced to the fields the daemon reads (CompactESLine); the
// counts go to the log once a minute. It returns errESBehind once records
// have trailed the clock by more than esMaxLag for esLagConfirm.
func pumpToSpoolAt(stdout interface{ Read([]byte) (int, error) }, path string) error {
	return pumpToSpoolObserved(stdout, path, nil)
}

func pumpToSpoolObserved(stdout interface{ Read([]byte) (int, error) }, path string, delivered func()) error {
	w := &spoolWriter{path: path}
	// Open WITHOUT rotating: the spool may hold events the tailer has not
	// drained yet (this process may have crash-looped; destroying unread
	// data on every respawn loses evidence). Rotation happens on
	// size only, inside writeLine.
	if err := w.open(); err != nil {
		return err
	}
	defer w.close()
	buf := make([]byte, 0, 256*1024)
	tmp := make([]byte, 64*1024)
	var compact []byte
	var stats esFilterStats
	var lag esLagWatch
	// overlong is set while the rest of a line past esMaxLine is discarded.
	overlong := false
	for {
		n, err := stdout.Read(tmp)
		wrote := false
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			start := 0
			for {
				nl := bytes.IndexByte(buf[start:], '\n')
				if nl < 0 {
					if len(buf)-start > esMaxLine {
						start, overlong = len(buf), true
					}
					break
				}
				// line aliases buf, so it is written before buf is compacted.
				line := buf[start : start+nl]
				start += nl + 1
				if overlong {
					overlong = false // the tail of a discarded line
					continue
				}
				if len(bytes.TrimSpace(line)) > 0 { // empty lines are skipped
					if err := lag.check(line); err != nil {
						return err
					}
					if keepESLine(line) {
						// Only the fields the daemon reads reach the spool; a
						// line that is not one JSON object goes as it is.
						out := line
						if c, ok := collect.CompactESLine(compact[:0], line); ok {
							compact, out = c, c
						}
						if err := w.writeLine(out); err != nil {
							return fmt.Errorf("spool write: %w", err)
						}
						stats.kept++
						stats.keptBytes += uint64(len(line))
						stats.wroteBytes += uint64(len(out))
						wrote = true
					} else {
						stats.dropped++
					}
					if msg, ok := stats.report(time.Now()); ok {
						log.Print(msg)
					}
				}
			}
			buf = append(buf[:0], buf[start:]...)
		}
		if wrote {
			if err := w.flush(); err != nil {
				return fmt.Errorf("spool write: %w", err)
			}
			if delivered != nil {
				delivered()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("eslogger read: %w", err)
		}
	}
}

// esLagWatch samples records once per esLagCheckInterval and reports
// eslogger behind once every sample for esLagConfirm trailed the clock by
// more than esMaxLag.
type esLagWatch struct {
	next        time.Time
	behindSince time.Time
}

func (w *esLagWatch) check(line []byte) error {
	now := esNow()
	if now.Before(w.next) {
		return nil
	}
	w.next = now.Add(esLagCheckInterval)
	at, ok := esLineTime(line)
	if !ok {
		return nil
	}
	lag := now.Sub(at)
	if lag <= esMaxLag {
		w.behindSince = time.Time{}
		return nil
	}
	if w.behindSince.IsZero() {
		w.behindSince = now
	}
	if now.Sub(w.behindSince) < esLagConfirm {
		return nil
	}
	return fmt.Errorf("%w: its newest event happened at %s, %s ago", errESBehind, at.UTC().Format(time.RFC3339), lag.Round(time.Second))
}

var esTimeMarker = []byte(`"time":"`)

// esLineTime reads an eslogger record's event time without decoding it. The
// envelope's "time" key occurs once, after the process object (whose own
// times are keyed start_time); a quote inside a string value is escaped, so
// the marker cannot match inside one.
func esLineTime(line []byte) (time.Time, bool) {
	i := bytes.Index(line, esTimeMarker)
	if i < 0 {
		return time.Time{}, false
	}
	rest := line[i+len(esTimeMarker):]
	j := bytes.IndexByte(rest, '"')
	if j < 0 {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, string(rest[:j]))
	return at, err == nil
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
