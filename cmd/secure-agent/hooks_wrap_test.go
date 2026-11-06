package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

const wrapSecret = "PROMPT-TEXT-never-recorded"

// wrapRun runs the wrapper over a shell hook and returns its exit status,
// stdout, stderr and the records it appended.
func wrapRun(t *testing.T, input, shell string, extra ...string) (int, string, string, []hookrun.Record) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "activity.jsonl")
	clock := []time.Time{time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC), time.Date(2026, 10, 21, 15, 0, 0, 12e6, time.UTC)}
	now := func() time.Time { t := clock[0]; clock = clock[1:]; return t }
	args := append([]string{"--harness", "codex", "--output", log}, extra...)
	args = append(args, "--", "/bin/sh", "-c", shell)
	var stdout, stderr bytes.Buffer
	code := runHookWrap(strings.NewReader(input), &stdout, &stderr, args, now)
	var recs []hookrun.Record
	if f, err := os.Open(log); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if strings.Contains(sc.Text(), wrapSecret) {
				t.Fatalf("record carries hook input or output: %s", sc.Text())
			}
			r, ok, err := hookrun.DecodeRecord(sc.Bytes())
			if !ok || err != nil {
				t.Fatalf("record %s: ok=%v err=%v", sc.Text(), ok, err)
			}
			recs = append(recs, r)
		}
	}
	return code, stdout.String(), stderr.String(), recs
}

func TestHookWrapPassesThroughAndRecords(t *testing.T) {
	prompt := `{"session_id":"s-1","hook_event_name":"UserPromptSubmit","prompt":"` + wrapSecret + `"}`
	// The hook sees its input, its stdout and exit status come back unchanged,
	// and the injected context is counted in characters, not recorded.
	code, out, _, recs := wrapRun(t, prompt, `grep -q `+wrapSecret+` && printf 'ctx ✓'`, "--script", "/x/check.py")
	if code != 0 || out != "ctx ✓" {
		t.Fatalf("exit %d stdout %q, want 0 and the hook's own output", code, out)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %+v, want one", recs)
	}
	r := recs[0]
	if r.Harness != "codex" || r.SessionID != "s-1" || r.Event != "UserPromptSubmit" || r.Script != "check.py" ||
		r.Status != "inject" || r.Chars != 5 || r.DurationMs != 12 || !strings.HasPrefix(r.ID, "codex:") {
		t.Fatalf("record = %+v", r)
	}

	pre := `{"session_id":"s-1","hook_event_name":"PreToolUse"}`
	for _, c := range []struct {
		shell, status string
		code          int
	}{
		{`echo denied >&2; exit 2`, "block", 2},
		{`exit 1`, "error", 1},
		{`echo '{"hookSpecificOutput":{"permissionDecision":"deny"}}'`, "deny", 0},
		{`echo '{"decision":"block","reason":"no"}'`, "block", 0},
		{`echo not-context`, "ok", 0},
	} {
		code, _, stderr, recs := wrapRun(t, pre, c.shell)
		if code != c.code || len(recs) != 1 || recs[0].Status != c.status || recs[0].Script != "" {
			t.Fatalf("%s: exit %d records %+v, want exit %d and %s", c.shell, code, recs, c.code, c.status)
		}
		if c.code == 2 && stderr != "denied\n" {
			t.Fatalf("stderr = %q, want the hook's own", stderr)
		}
	}

	// Input naming no session still runs the hook; nothing is recorded.
	if code, out, _, recs := wrapRun(t, `not json`, `echo ran`); code != 0 || out != "ran\n" || len(recs) != 0 {
		t.Fatalf("unrecognized input: exit %d stdout %q records %+v", code, out, recs)
	}
}

func TestHookWrapRejectsUsage(t *testing.T) {
	var stderr bytes.Buffer
	if code := runHookWrap(strings.NewReader(""), &bytes.Buffer{}, &stderr, []string{"--harness", "nope", "--", "true"}, time.Now); code != 1 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("exit %d stderr %q", code, stderr.String())
	}
}
