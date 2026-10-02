package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// chunkReader returns one chunk per Read call, then io.EOF.
type chunkReader struct {
	chunks []string
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

func TestPumpToSpoolWritesEachRecordIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	r := &chunkReader{chunks: []string{`{"a":1}` + "\n" + `{"b":2}` + "\n" + `{"c":`, "3}\n"}}

	if err := pumpToSpoolAt(r, path); err != nil {
		t.Fatalf("pumpToSpoolAt: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	want := `{"a":1}` + "\n" + `{"b":2}` + "\n" + `{"c":3}` + "\n"
	if string(got) != want {
		t.Fatalf("spool = %q, want %q", got, want)
	}
	for i, line := range bytes.Split(bytes.TrimSuffix(got, []byte("\n")), []byte("\n")) {
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("line %d %q is not a JSON object: %v", i, line, err)
		}
	}
}

func TestIsESCollectorInvocation(t *testing.T) {
	cases := []struct {
		argv0 string
		flag  bool
		want  bool
	}{
		{"/Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd", false, true},
		{"secure-agent-esd", false, true},
		{"/Applications/Secure Agent.app/Contents/Helpers/secure-agentd", false, false},
		{"/Library/PrivilegedHelperTools/com.cavi-ai.secure-agent-esd", true, true},
		{"/usr/local/bin/secure-agent-esd-old", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := isESCollectorInvocation(c.argv0, c.flag); got != c.want {
			t.Errorf("isESCollectorInvocation(%q, %v) = %v, want %v", c.argv0, c.flag, got, c.want)
		}
	}
}

// stubCodesign replaces the signature check for one test and records the
// path it was asked about.
func stubCodesign(t *testing.T, result error) *string {
	t.Helper()
	var asked string
	prev := codesignVerify
	codesignVerify = func(path string) error {
		asked = path
		return result
	}
	t.Cleanup(func() { codesignVerify = prev })
	return &asked
}

func TestVerifyExecutableAcceptsSignedNonWritableBinary(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "secure-agent-esd")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	asked := stubCodesign(t, nil)
	if err := verifyExecutable(exe); err != nil {
		t.Fatalf("verifyExecutable: %v", err)
	}
	if *asked != exe {
		t.Fatalf("codesign verified %q, want %q", *asked, exe)
	}
}

func TestVerifyExecutableRefusesFailedSignature(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "secure-agent-esd")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubCodesign(t, errors.New("invalid signature (code or signature have been modified)"))
	err := verifyExecutable(exe)
	if err == nil || !strings.Contains(err.Error(), "code signature") {
		t.Fatalf("verifyExecutable = %v, want a code signature refusal", err)
	}
	if !IsESPermanentFailure(permanent(err)) {
		t.Fatal("a signature refusal must be permanent so launchd leaves the service stopped")
	}
}

func TestVerifyExecutableRefusesWritableBinary(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "secure-agent-esd")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o775); err != nil {
		t.Fatal(err)
	}
	asked := stubCodesign(t, nil)
	err := verifyExecutable(exe)
	if err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("verifyExecutable = %v, want a writable-binary refusal", err)
	}
	if *asked != "" {
		t.Fatal("a writable binary must be refused before the signature check")
	}
}

func TestCodesignVerifyRealSignatures(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign not available")
	}
	if err := codesignVerify("/bin/ls"); err != nil {
		t.Fatalf("codesign --verify rejected a signed system binary: %v", err)
	}
	f := filepath.Join(t.TempDir(), "unsigned")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := codesignVerify(f); err == nil {
		t.Fatal("codesign --verify accepted an unsigned file")
	}
}

// esRecord is an eslogger exec record (kept by the filter) with its process
// start_time ahead of the envelope's own time, as eslogger orders them.
func esRecord(at time.Time) string {
	return `{"process":{"start_time":"2026-10-01T00:00:00Z","audit_token":{"pid":7}},"time":"` + at.Format(time.RFC3339Nano) + `","event":{"exec":{}}}`
}

// tickingClock returns a clock that advances by step on every read.
func tickingClock(start time.Time, step time.Duration) func() time.Time {
	now := start
	return func() time.Time {
		at := now
		now = now.Add(step)
		return at
	}
}

func esRecords(n int, at func(i int) time.Time) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(esRecord(at(i)) + "\n")
	}
	return b.String()
}

// An eslogger that has fallen behind is stopped, not followed: the pump
// returns errESBehind once sampled records have trailed the clock by more
// than esMaxLag for esLagConfirm.
func TestPumpToSpoolStopsAnESLoggerThatFellBehind(t *testing.T) {
	now := time.Date(2026, 10, 2, 21, 43, 0, 0, time.UTC)
	t.Cleanup(func() { esNow = time.Now })

	path := filepath.Join(t.TempDir(), "spool.jsonl")
	esNow = tickingClock(now, time.Second)
	fresh := &chunkReader{chunks: []string{esRecords(60, func(i int) time.Time { return now.Add(time.Duration(i) * time.Second) })}}
	if err := pumpToSpoolAt(fresh, path); err != nil {
		t.Fatalf("records within esMaxLag: %v", err)
	}

	esNow = tickingClock(now, time.Second)
	behind := &chunkReader{chunks: []string{esRecords(60, func(i int) time.Time { return now.Add(-2*time.Hour - 13*time.Minute) })}}
	err := pumpToSpoolAt(behind, path)
	if !errors.Is(err, errESBehind) || !strings.Contains(err.Error(), "19:30:00Z") {
		t.Fatalf("records 2h13m behind: err = %v, want errESBehind naming the event time", err)
	}
	got, _ := os.ReadFile(path)
	if n := strings.Count(string(got), "\n"); n != 60+int(esLagConfirm/time.Second) {
		t.Fatalf("spool has %d records, want the fresh 60 plus the %s of stale ones before the restart", n, esLagConfirm)
	}
}

// Records held in the pipe across a sleep read stale once on wake, then
// fresh ones follow: that is not an eslogger behind.
func TestPumpToSpoolKeepsAnESLoggerAfterWake(t *testing.T) {
	now := time.Date(2026, 10, 2, 21, 43, 0, 0, time.UTC)
	esNow = tickingClock(now, time.Second)
	t.Cleanup(func() { esNow = time.Now })
	stream := esRecords(5, func(int) time.Time { return now.Add(-time.Hour) }) +
		esRecords(60, func(i int) time.Time { return now.Add(time.Duration(5+i) * time.Second) })
	if err := pumpToSpoolAt(&chunkReader{chunks: []string{stream}}, filepath.Join(t.TempDir(), "spool.jsonl")); err != nil {
		t.Fatalf("stale records after wake: %v", err)
	}
}

// Every pump closes its spool file: the collector reopens it on each
// eslogger restart. GC is off so a finalizer cannot close a leaked file.
func TestPumpToSpoolClosesTheSpool(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	openFDs := func() int {
		entries, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Skip("no /dev/fd")
		}
		return len(entries)
	}
	before := openFDs()
	for i := 0; i < 20; i++ {
		if err := pumpToSpoolAt(&chunkReader{chunks: []string{`{"a":1}` + "\n"}}, path); err != nil {
			t.Fatal(err)
		}
	}
	if after := openFDs(); after-before >= 20 {
		t.Fatalf("open descriptors %d -> %d over 20 pumps", before, after)
	}
}

func TestESLineTimeReadsTheEnvelopeTime(t *testing.T) {
	at := time.Date(2026, 10, 2, 19, 30, 41, 256436034, time.UTC)
	if got, ok := esLineTime([]byte(esRecord(at))); !ok || !got.Equal(at) {
		t.Fatalf("esLineTime = %s, %v; want %s", got, ok, at)
	}
	for _, line := range []string{`{"a":1}`, `{"time":"not a time"}`, `{"time":"2026-10-02T19:30:41Z`} {
		if _, ok := esLineTime([]byte(line)); ok {
			t.Fatalf("esLineTime(%q) ok, want false", line)
		}
	}
}

// One timestamp read per esLagCheckInterval; a fresh sample resets the run.
func TestESLagWatchSamplesAndConfirms(t *testing.T) {
	now := time.Date(2026, 10, 2, 21, 43, 0, 0, time.UTC)
	esNow = func() time.Time { return now }
	t.Cleanup(func() { esNow = time.Now })
	var w esLagWatch
	stale := []byte(esRecord(now.Add(-time.Hour)))
	if err := w.check(stale); err != nil {
		t.Fatalf("first stale sample: %v", err)
	}
	now = now.Add(esLagConfirm / 2)
	if err := w.check([]byte(esRecord(now))); err != nil {
		t.Fatal(err)
	}
	now = now.Add(esLagConfirm)
	if err := w.check(stale); err != nil {
		t.Fatalf("a fresh sample in between did not reset the run: %v", err)
	}
	if err := w.check(stale); err != nil {
		t.Fatalf("checked again inside the interval: %v", err)
	}
	now = now.Add(esLagConfirm)
	if err := w.check(stale); !errors.Is(err, errESBehind) {
		t.Fatalf("stale for esLagConfirm: err = %v, want errESBehind", err)
	}
}
