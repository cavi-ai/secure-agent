package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

// maxWrapInput bounds the hook input read from stdin (hook payloads are small).
const maxWrapInput = 8 << 20

const hookWrapUsage = "usage: secure-agent hooks wrap --harness codex [--script NAME] [--output path] -- COMMAND [ARGS...]"

// runHookWrap runs one configured hook command unchanged and records its
// completion: stdin reaches the command as given, and its stdout, stderr and
// exit status come back untouched. Only the session, event, script label,
// outcome, duration and returned-character count are recorded; arguments and
// output never are. A recording failure never changes the hook's result.
// Returns the exit status to leave with.
func runHookWrap(in io.Reader, stdout, stderr io.Writer, args []string, now func() time.Time) int {
	flags := flag.NewFlagSet("hooks wrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harness := flags.String("harness", "", "harness the hook belongs to")
	script := flags.String("script", "", "script label recorded for the handler")
	output := flags.String("output", "", "activity log path")
	if flags.Parse(args) != nil || flags.NArg() == 0 || !hookHarness(*harness) {
		fmt.Fprintln(stderr, hookWrapUsage)
		return 1
	}
	command := flags.Args()

	input, err := io.ReadAll(io.LimitReader(in, maxWrapInput+1))
	if err != nil || len(input) > maxWrapInput {
		fmt.Fprintln(stderr, "secure-agent hooks wrap: cannot read hook input")
		return 1
	}
	start := now()
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = stderr
	runErr := cmd.Run()
	end := now()
	_, _ = stdout.Write(out.Bytes())

	code := 0
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exitErr):
		code = exitErr.ExitCode()
		if code < 0 {
			code = 1
		}
	default:
		fmt.Fprintln(stderr, "secure-agent hooks wrap: cannot run the hook command")
		code = 1
	}

	if rec, ok := wrapRecord(*harness, *script, input, out.Bytes(), code, start, end); ok {
		_ = appendHookRecord(*output, rec)
	}
	return code
}

// hookHarness reports whether the shared record contract accepts harness.
func hookHarness(harness string) bool {
	probe := hookrun.Record{Type: "hook_run", Version: 1, Harness: harness, SessionID: "s", ID: "probe:1",
		TS: time.Unix(1, 0), Event: "probe", Status: "ok"}
	return probe.Validate() == nil
}

// wrapInput is the hook input subset the wrapper reads.
type wrapInput struct {
	SessionID string `json:"session_id"`
	Event     string `json:"hook_event_name"`
}

// wrapOutput is the hook output subset that decides the outcome.
type wrapOutput struct {
	Decision           string `json:"decision"`
	HookSpecificOutput struct {
		PermissionDecision string `json:"permissionDecision"`
		AdditionalContext  string `json:"additionalContext"`
	} `json:"hookSpecificOutput"`
}

// wrapRecord builds the completion record, or ok=false when the input names
// no session or event. Outcomes follow the hook protocol Codex shares with
// Claude Code: exit 2 blocks, another nonzero exit is an error; on exit 0 a
// JSON decision "block" blocks, permissionDecision "deny" denies, and text
// added to the model's context (plain stdout of a prompt or session-start
// hook, or additionalContext) is an injection counted in characters.
func wrapRecord(harness, script string, input, output []byte, code int, start, end time.Time) (hookrun.Record, bool) {
	var in wrapInput
	if json.Unmarshal(input, &in) != nil || in.SessionID == "" || in.Event == "" {
		return hookrun.Record{}, false
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return hookrun.Record{}, false
	}
	id, err := hookrun.ExecutionID(harness, hex.EncodeToString(raw[:]))
	if err != nil {
		return hookrun.Record{}, false
	}
	rec := hookrun.Record{Type: "hook_run", Version: 1, Harness: harness, SessionID: in.SessionID, ID: id,
		TS: end.UTC(), Event: in.Event, Script: filepath.Base(script), Status: "ok",
		DurationMs: end.Sub(start).Milliseconds()}
	if script == "" {
		rec.Script = ""
	}
	text := strings.TrimSpace(string(output))
	var out wrapOutput
	isJSON := strings.HasPrefix(text, "{") && json.Unmarshal([]byte(text), &out) == nil
	switch {
	case code == 2:
		rec.Status = "block"
	case code != 0:
		rec.Status = "error"
	case isJSON && out.Decision == "block":
		rec.Status = "block"
	case isJSON && out.HookSpecificOutput.PermissionDecision == "deny":
		rec.Status = "deny"
	case isJSON && out.HookSpecificOutput.AdditionalContext != "":
		rec.Status, rec.Chars = "inject", int64(utf8.RuneCountInString(out.HookSpecificOutput.AdditionalContext))
	case !isJSON && text != "" && (in.Event == "UserPromptSubmit" || in.Event == "SessionStart"):
		rec.Status, rec.Chars = "inject", int64(utf8.RuneCountInString(text))
	}
	if rec.Validate() != nil {
		return hookrun.Record{}, false
	}
	return rec, true
}

// appendHookRecord appends one record line to the activity log the daemon
// tails (output, else the default path).
func appendHookRecord(output string, rec hookrun.Record) error {
	if output == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		output = filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	// One append keeps concurrent hooks from interleaving.
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
