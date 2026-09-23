package collect

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// drainSpool runs a tailer against a test spool until want events arrive or
// the timeout fires; returns what it collected.
func drainSpool(t *testing.T, lines []string, want int, timeout time.Duration) []event.Event {
	t.Helper()
	path := t.TempDir() + "/spool.jsonl"
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	b := bus.New(64)
	tailer := NewSpoolTailerAt(b, path)
	go func() { _ = tailer.Run(context.Background()) }()
	var got []event.Event
	sub := b.Subscribe()
	deadline := time.After(timeout)
	for {
		select {
		case e := <-sub:
			got = append(got, e)
			if len(got) >= want {
				return got
			}
		case <-deadline:
			return got
		}
	}
}

func TestParseLaunchctlStateTakesFirstTopLevelState(t *testing.T) {
	// launchctl print output carries the service state at one tab of
	// indentation; nested sections (endpoints, mach services) repeat the
	// key at deeper indentation. A crash-looping service reads as
	// "spawn scheduled" only when the FIRST top-level state wins.
	out := "system/com.cavi-ai.secure-agent-esd = {\n" +
		"\tactive count = 1\n" +
		"\tpath = /Library/LaunchDaemons/com.cavi-ai.secure-agent-esd.plist\n" +
		"\tstate = spawn scheduled\n" +
		"\n" +
		"\tprogram = /Library/PrivilegedHelperTools/com.cavi-ai.secure-agent-esd\n" +
		"\tlast exit code = 1\n" +
		"\tmach services = {\n" +
		"\t\tcom.example = {\n" +
		"\t\t\tstate = running\n" +
		"\t\t}\n" +
		"\t}\n" +
		"}\n"
	if got := parseLaunchctlState(out); got != "spawn scheduled (last exit 1)" {
		t.Fatalf("state = %q, want spawn scheduled (last exit 1)", got)
	}
	// Clean exit: no annotation.
	clean := "\tstate = running\n\tlast exit code = 0\n"
	if got := parseLaunchctlState(clean); got != "running" {
		t.Fatalf("state = %q, want running", got)
	}
}

func TestParseLaunchctlProgramTakesTopLevelAbsolutePath(t *testing.T) {
	out := "system/com.cavi-ai.secure-agent-esd = {\n" +
		"\tactive count = 1\n" +
		"\tstate = running\n" +
		"\tprogram = /Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd\n" +
		"\tendpoints = {\n" +
		"\t\tprogram = /usr/libexec/other\n" +
		"\t}\n" +
		"}\n"
	if got := parseLaunchctlProgram(out); got != "/Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd" {
		t.Fatalf("program = %q", got)
	}
	nested := "\tstate = running\n\tendpoints = {\n\t\tprogram = /usr/libexec/other\n\t}\n"
	if got := parseLaunchctlProgram(nested); got != "" {
		t.Fatalf("nested-only program = %q, want empty", got)
	}
	if got := parseLaunchctlProgram("\tprogram = relative/path\n"); got != "" {
		t.Fatalf("relative program = %q, want empty", got)
	}
}

func TestHelperMtimeStatsTheLaunchctlProgram(t *testing.T) {
	helper := t.TempDir() + "/secure-agent-esd"
	if err := os.WriteFile(helper, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(helper, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	out := "system/com.cavi-ai.secure-agent-esd = {\n\tstate = running\n\tprogram = " + helper + "\n}\n"
	if got := helperMtime(out); !got.Equal(stamp) {
		t.Fatalf("helperMtime = %v, want %v", got, stamp)
	}
	if got := helperMtime("\tstate = running\n"); !got.IsZero() {
		t.Fatalf("no program line: helperMtime = %v, want zero", got)
	}
	if got := helperMtime("\tprogram = " + helper + ".missing\n"); !got.IsZero() {
		t.Fatalf("missing program file: helperMtime = %v, want zero", got)
	}
}

func TestSpoolTailerParsesAndPublishes(t *testing.T) {
	// An ES open-event envelope exactly like eslogger emits.
	line := `{"event_type":0,"process":{"audit_token":{"pid":4242},"pid":4242,"executable":{"path":"/usr/bin/cat"}},"event":{"open":{"file":{"path":"/Users/x/.ssh/id_ed25519"}}},"time":"2026-09-11T12:00:00.000000Z"}`
	got := drainSpool(t, []string{line}, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Kind != 0 || got[0].PID != 4242 || got[0].Path != "/Users/x/.ssh/id_ed25519" {
		t.Fatalf("wrong event decoded: %+v", got[0])
	}
}

func TestSpoolTailerHandlesRotationAndGarbage(t *testing.T) {
	// Malformed lines must not kill the tail; partial lines across reads are
	// handled by the line-scanner (no event, no crash).
	line := `{"event_type":0,"process":{"audit_token":{"pid":7},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}`
	got := drainSpool(t, []string{"not json", "{broken", line, ""}, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 event amid garbage, got %d", len(got))
	}
	if got[0].PID != 7 {
		t.Fatalf("wrong pid: %+v", got[0])
	}
}

// An unchanged spool is not opened: the tick costs one stat. A spool whose
// size or mtime moved is drained, and a rotated spool is re-read from 0.
func TestSpoolPollSkipsUnchangedSpool(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	line := func(pid int) string {
		return fmt.Sprintf(`{"event_type":0,"process":{"audit_token":{"pid":%d},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}`+"\n", pid)
	}
	if err := os.WriteFile(path, []byte(line(1)), 0o640); err != nil {
		t.Fatal(err)
	}
	b := bus.New(64)
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	opens := 0
	tailer.open = func(p string) (*os.File, error) {
		opens++
		return os.Open(p)
	}
	expect := func(pid int32) {
		t.Helper()
		select {
		case e := <-sub:
			if e.PID != pid {
				t.Fatalf("drained pid %d, want %d", e.PID, pid)
			}
		default:
			t.Fatalf("no event drained, want pid %d", pid)
		}
	}

	var c spoolCursor
	c = tailer.poll(c)
	expect(1)
	for i := 0; i < 5; i++ {
		c = tailer.poll(c)
	}
	if opens != 1 {
		t.Fatalf("spool opened %d times across 5 unchanged ticks; want 1 (the first drain)", opens)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line(2)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	c = tailer.poll(c)
	expect(2)
	if opens != 2 {
		t.Fatalf("changed spool: %d opens, want 2", opens)
	}

	// Rotation: a shorter new file resets the offset, then is read from 0.
	if err := os.WriteFile(path, []byte(line(3)), 0o640); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, future, future)
	for i := 0; i < 3; i++ {
		c = tailer.poll(c)
	}
	expect(3)
}

// A flooding spool (a defective writer's near-empty garbage lines, far past
// the per-tick drain budget) is drained past the budget and the rest of the
// tail skipped in one tick — not scanned line by line — and reported via
// Stats(). A following tick with real lines drains normally and clears the
// flood signal.
func TestSpoolTailerSkipsFloodPastBudget(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	body := bytes.Repeat([]byte("ab\n"), (10<<20)/3) // ~10 MiB of 2-byte lines
	if err := os.WriteFile(path, body, 0o640); err != nil {
		t.Fatal(err)
	}
	b := bus.New(64)
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)

	c := tailer.poll(spoolCursor{})
	if c.offset != int64(len(body)) {
		t.Fatalf("offset after flood tick = %d, want EOF %d", c.offset, len(body))
	}
	stats := tailer.Stats()
	if stats.BytesSkipped == 0 {
		t.Fatal("BytesSkipped = 0 after a tick well past the drain budget, want > 0")
	}
	if stats.FloodSince.IsZero() {
		t.Fatal("FloodSince not set after a flooding tick")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"event_type":0,"process":{"audit_token":{"pid":9},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}` + "\n"
	for i := 0; i < 100; i++ {
		if _, err := f.WriteString(valid); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	c = tailer.poll(c)
	if c.offset != int64(len(body))+int64(len(valid))*100 {
		t.Fatalf("offset after clean tick = %d, want end of the appended lines", c.offset)
	}
	stats = tailer.Stats()
	if stats.Parsed != 100 {
		t.Fatalf("Parsed = %d, want 100 — the valid lines must still be drained after a flood", stats.Parsed)
	}
	if !stats.FloodSince.IsZero() {
		t.Fatal("FloodSince not cleared after a tick that drained fully within budget")
	}
	select {
	case e := <-sub:
		if e.PID != 9 {
			t.Fatalf("published event pid = %d, want 9", e.PID)
		}
	default:
		t.Fatal("no parsed event published after the flood cleared")
	}
}
