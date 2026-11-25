package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const recordedDaemonEnv = "SECURE_AGENT_FAKE_DAEMON_DIR"

func appendEvent(dir, line string) {
	f, err := os.OpenFile(filepath.Join(dir, "events"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}

// TestStopFakeDaemonProcess is the daemon the stop tests start: it serves the
// control socket, writes its run record, and logs requests and SIGTERM in order.
func TestStopFakeDaemonProcess(t *testing.T) {
	dir := os.Getenv(recordedDaemonEnv)
	if dir == "" {
		return
	}
	status, _ := strconv.Atoi(os.Getenv(recordedDaemonEnv + "_STATUS"))
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	ln, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		os.Exit(2)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appendEvent(dir, r.Method+" "+r.URL.Path)
		if status != http.StatusOK {
			http.Error(w, "forbidden: this endpoint requires a more privileged client", status)
			return
		}
		fmt.Fprint(w, `{"recorded_at":"2026-01-01T00:00:00Z","valid_until":"2026-01-01T00:00:30Z"}`)
	}))
	rec, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "started_at": time.Now().UTC()})
	tmp := filepath.Join(dir, "record.tmp")
	if os.WriteFile(tmp, rec, 0o600) != nil || os.Rename(tmp, filepath.Join(dir, "run-record.json")) != nil {
		os.Exit(2)
	}
	select {
	case <-terms:
		appendEvent(dir, "SIGTERM")
		os.Exit(0)
	case <-time.After(30 * time.Second):
		os.Exit(3)
	}
}

type recordedDaemon struct {
	dir, sock, record string
	pid               int
	exited            chan struct{}
}

func (d recordedDaemon) events() []string {
	data, _ := os.ReadFile(filepath.Join(d.dir, "events"))
	return strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' })
}

func startFakeDaemon(t *testing.T, status int) recordedDaemon {
	t.Helper()
	// Unix socket paths are limited to 104 bytes; t.TempDir is too long here.
	dir, err := os.MkdirTemp("", "sa-stop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cmd := exec.Command(os.Args[0], "-test.run=^TestStopFakeDaemonProcess$")
	cmd.Env = append(os.Environ(), recordedDaemonEnv+"="+dir, recordedDaemonEnv+"_STATUS="+strconv.Itoa(status))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	d := recordedDaemon{dir: dir, sock: filepath.Join(dir, "d.sock"), record: filepath.Join(dir, "run-record.json"),
		pid: cmd.Process.Pid, exited: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(d.exited) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-d.exited })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(d.record); err == nil {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatal("fake daemon did not write its run record")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStopPostsIntentThenStopsRecordedDaemon(t *testing.T) {
	d := startFakeDaemon(t, http.StatusOK)
	var out bytes.Buffer
	if code := runStop(&out, d.sock, d.record, 5*time.Second); code != 0 {
		t.Fatalf("stop exited %d: %s", code, out.String())
	}
	select {
	case <-d.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("recorded daemon still running after stop")
	}
	if got, want := d.events(), []string{"POST /daemon/stop-intent", "SIGTERM"}; !slices.Equal(got, want) {
		t.Fatalf("daemon saw %q, want %q", got, want)
	}
	if !strings.Contains(out.String(), "pid "+strconv.Itoa(d.pid)) {
		t.Fatalf("output does not name the stopped pid: %s", out.String())
	}
}

func TestStopRefusedIntentStopsNothing(t *testing.T) {
	d := startFakeDaemon(t, http.StatusForbidden)
	var out bytes.Buffer
	if code := runStop(&out, d.sock, d.record, 5*time.Second); code == 0 {
		t.Fatalf("refused stop exited 0: %s", out.String())
	}
	if !strings.Contains(out.String(), "403") || !strings.Contains(out.String(), "forbidden") {
		t.Fatalf("output does not show the refusal: %s", out.String())
	}
	select {
	case <-d.exited:
		t.Fatal("refused stop signalled the daemon")
	case <-time.After(300 * time.Millisecond):
	}
	if got, want := d.events(), []string{"POST /daemon/stop-intent"}; !slices.Equal(got, want) {
		t.Fatalf("daemon saw %q, want %q", got, want)
	}
}

func TestStopSignalsNothingWhenSocketIsNotTheRecordedPID(t *testing.T) {
	d := startFakeDaemon(t, http.StatusOK)
	bystander := exec.Command("/bin/sleep", "30")
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	gone := make(chan struct{})
	go func() { _ = bystander.Wait(); close(gone) }()
	t.Cleanup(func() { _ = bystander.Process.Kill(); <-gone })
	rec, _ := json.Marshal(map[string]any{"pid": bystander.Process.Pid, "started_at": time.Now().UTC()})
	if err := os.WriteFile(d.record, rec, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := runStop(&out, d.sock, d.record, 5*time.Second); code == 0 {
		t.Fatalf("stop exited 0 for a pid that does not serve the socket: %s", out.String())
	}
	select {
	case <-gone:
		t.Fatal("stop signalled a process that is not the daemon")
	case <-d.exited:
		t.Fatal("stop signalled the socket's process without a matching record")
	case <-time.After(300 * time.Millisecond):
	}
	if got := d.events(); len(got) != 0 {
		t.Fatalf("stop posted %q to a daemon that does not match the record", got)
	}
}
