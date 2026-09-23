package collect

import (
	"context"
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
