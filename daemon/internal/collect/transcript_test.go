package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

func TestScanLineTranscriptHit(t *testing.T) {
	line := "some log output with Bearer sk-secrettoken123 in it"
	evs := (&TranscriptScanner{}).scanLine(line, "/logs/activity.jsonl", "unknown", "", 0)
	if len(evs) != 1 || evs[0].Kind != event.KindTranscriptHit {
		t.Fatalf("scanLine = %+v; want one KindTranscriptHit", evs)
	}
	e := evs[0]
	if e.Detail != "unknown:pattern:bearer-token" || e.Path != "/logs/activity.jsonl" {
		t.Fatalf("Detail = %q Path = %q, want unknown:pattern:bearer-token on the tailed path", e.Detail, e.Path)
	}
	if strings.Contains(e.Detail, "sk-secrettoken123") {
		t.Fatal("secret token leaked into event detail!")
	}
}

func TestScanLinePluginAction(t *testing.T) {
	line := `{"ts":"2026-08-12T19:55:00Z","tool":"Bash","command":"ls"}`
	evs := (&TranscriptScanner{}).scanLine(line, "/logs/activity.jsonl", "unknown", "", 0)
	if len(evs) != 1 || evs[0].Kind != event.KindPluginAction {
		t.Fatalf("scanLine = %+v; want one KindPluginAction", evs)
	}
	e := evs[0]
	if e.Detail != "Bash" {
		t.Fatalf("Detail = %q, want Bash", e.Detail)
	}
}

// TestScannerTailsActiveFile locks the split-cadence refactor: a recently
// modified file stays in the active set and lines appended after startup are
// captured, while pre-existing content seeded past on startup is not replayed.
func TestScannerTailsActiveFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.jsonl")

	// Pre-existing content must be seeded past, not replayed onto the bus.
	if err := os.WriteFile(logPath, []byte(`{"tool":"OldTool"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{filepath.Join(dir, "*.jsonl")})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)

	// Append after the scanner has started and seeded existing content to EOF.
	time.Sleep(250 * time.Millisecond)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"tool":"Bash","command":"whoami"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	select {
	case e := <-sub:
		if e.Kind != event.KindPluginAction || e.Detail != "Bash" {
			t.Fatalf("got kind=%v detail=%q, want KindPluginAction/Bash", e.Kind, e.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scanner did not publish the appended transcript line")
	}
}

// A line longer than the reader's buffer must still parse. Regression: lines
// over 4 KB were counted toward the offset and skipped — real prompt records
// run 10 KB+, so turn detection silently saw none of them.
func TestOverlongLineStillParses(t *testing.T) {
	dir := t.TempDir()
	projectsDir := filepath.Join(dir, ".claude", "projects")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(projectsDir, "session.jsonl")
	if err := os.WriteFile(logPath, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{logPath})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)

	// Append a 12 KB user-prompt record after the seed.
	time.Sleep(250 * time.Millisecond)
	long := strings.Repeat("x", 12000)
	line := `{"sessionId":"turn-long","type":"user","timestamp":"2026-09-20T17:44:53.118Z","message":{"content":"` + long + `"}}` + "\n"
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	f.Close()

	for {
		select {
		case e := <-sub:
			if e.Kind == event.KindTurn {
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("overlong prompt line was skipped, no turn published")
		}
	}
}

// A prompt appended to a transcript that was IDLE past the active window must
// still produce a turn. Regression: the resolve tick re-seeded every file's
// offset to EOF, so the appended line — the one that made the file active
// again — was skipped, and the prompt never became a turn.
func TestIdleFileAppendIsNotSkipped(t *testing.T) {
	dir := t.TempDir()
	projectsDir := filepath.Join(dir, ".claude", "projects")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(projectsDir, "session.jsonl")
	seedLine := `{"sessionId":"idle-s","type":"user","timestamp":"2026-09-20T17:44:53.118Z","isMeta":true,"message":{"content":"meta"}}` + "\n"
	if err := os.WriteFile(logPath, []byte(seedLine), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{projectsDir})
	ts.tailEvery = 20 * time.Millisecond
	ts.resolveEvery = 50 * time.Millisecond
	ts.activeWindowD = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)

	// Let the scanner seed the file, then age it out of the active set.
	time.Sleep(200 * time.Millisecond)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(logPath, old, old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // a resolve tick with the file inactive

	// The append that ends the idle gap: a real prompt record.
	line := `{"sessionId":"idle-s","type":"user","timestamp":"2026-09-20T17:45:53.118Z","message":{"content":"fix the thing"}}` + "\n"
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	f.Close()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-sub:
			if e.Kind == event.KindTurn && e.SessionID == "idle-s" {
				return
			}
		case <-deadline:
			t.Fatal("prompt appended after an idle gap was skipped — no turn published")
		}
	}
}

// A transcript created AFTER the scanner started is read from byte 0 — its
// whole content is new, so the first prompt must land.
func TestNewSessionFileReadFromStart(t *testing.T) {
	dir := t.TempDir()
	projectsDir := filepath.Join(dir, ".claude", "projects")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{projectsDir})
	ts.tailEvery = 20 * time.Millisecond
	ts.resolveEvery = 50 * time.Millisecond
	ts.activeWindowD = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)
	time.Sleep(200 * time.Millisecond)

	logPath := filepath.Join(projectsDir, "brand-new.jsonl")
	line := `{"sessionId":"new-s","type":"user","timestamp":"2026-09-20T17:46:53.118Z","message":{"content":"first prompt"}}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-sub:
			if e.Kind == event.KindTurn && e.SessionID == "new-s" {
				return
			}
		case <-deadline:
			t.Fatal("new session transcript was not read from byte 0")
		}
	}
}

func TestScanLineFakeCursorActivity(t *testing.T) {
	line := `{"file_path":"/tmp/foo/.env","pid":12345,"tool":"Read"}`
	evs := (&TranscriptScanner{}).scanLine(line, "/logs/activity.jsonl", "unknown", "", 0)
	if len(evs) != 1 || evs[0].Kind != event.KindPluginAction {
		t.Fatalf("scanLine = %+v; want one KindPluginAction", evs)
	}
	e := evs[0]
	if e.PID != 12345 {
		t.Fatalf("PID = %d, want 12345", e.PID)
	}
	if e.Path != "/tmp/foo/.env" {
		t.Fatalf("Path = %q, want /tmp/foo/.env", e.Path)
	}
}

func TestParseHandshake(t *testing.T) {
	line := `{"type":"session_start","ts":"2026-09-17T12:00:00Z","session_id":"abc","harness":"claude","workspace":"/repo","repo":"repo","branch":"main","pid":4242}`
	h, ok := ParseHandshake(line)
	if !ok {
		t.Fatal("handshake not recognized")
	}
	if h.SessionID != "abc" || h.Harness != "claude" || h.Workspace != "/repo" || h.Repo != "repo" || h.Branch != "main" || h.PID != 4242 {
		t.Fatalf("handshake = %+v", h)
	}

	// A regular activity line is not a handshake.
	if _, ok := ParseHandshake(`{"tool":"Read","pid":1,"session_id":"abc"}`); ok {
		t.Fatal("activity line misclassified as handshake")
	}
	// A handshake without a session id is useless — drop it.
	if _, ok := ParseHandshake(`{"type":"session_start","harness":"claude"}`); ok {
		t.Fatal("handshake without session_id must not parse")
	}
}

// Lines appended while the daemon is down must not be lost: with a persisted
// offset file the restarted scanner resumes where the last run stopped
// instead of re-seeding the transcript at EOF.
func TestOffsetsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.jsonl")
	statePath := filepath.Join(dir, "offsets.json")

	if err := os.WriteFile(logPath, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b1 := bus.New(16)
	sub1 := b1.Subscribe()
	ts1 := NewTranscriptScanner(b1, []string{logPath})
	ts1.OffsetStatePath = statePath
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() { _ = ts1.Run(ctx1); close(done1) }()
	time.Sleep(250 * time.Millisecond)

	// Appended while "up": read and offset advanced.
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"tool":"Read","file_path":"/a"}` + "\n")
	f.Close()
	select {
	case <-sub1:
	case <-time.After(3 * time.Second):
		t.Fatal("first scanner did not publish the appended line")
	}
	// The dirty-save fires on the next tail tick after the offset advances.
	time.Sleep(500 * time.Millisecond)
	cancel1()
	select {
	case <-done1:
	case <-time.After(5 * time.Second):
		t.Fatal("first scanner did not stop after cancel")
	}

	// Appended while "down": the line a fresh-start seed would skip.
	f, _ = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"tool":"Bash","command":"ls"}` + "\n")
	f.Close()

	b2 := bus.New(16)
	sub2 := b2.Subscribe()
	ts2 := NewTranscriptScanner(b2, []string{logPath})
	ts2.OffsetStatePath = statePath
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { _ = ts2.Run(ctx2); close(done2) }()
	defer func() {
		cancel2()
		select {
		case <-done2:
		case <-time.After(5 * time.Second):
			t.Fatal("second scanner did not stop after cancel")
		}
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case e := <-sub2:
			if e.Kind == event.KindPluginAction && e.Detail == "Bash" {
				return // the down-window line was picked up
			}
		case <-deadline:
			t.Fatal("line appended while the daemon was down was lost across restart")
		}
	}
}

// stubTextScanner reports a fingerprint hit (and an entropy hit, which the
// tailer must drop) for any text containing secret.
type stubTextScanner struct{ secret string }

func (s stubTextScanner) ScanText(text string) []firewall.Hit {
	if !strings.Contains(text, s.secret) {
		return nil
	}
	return []firewall.Hit{
		{RuleID: "fp-1", SecretType: firewall.TypeEnvValue, Layer: firewall.LayerFingerprint, Confidence: 1},
		{RuleID: "entropy", SecretType: firewall.TypeUnknown, Layer: firewall.LayerEntropy, Confidence: 0.4},
	}
}

// appendAndTail appends line to path and runs one tail pass, returning the
// transcript-hit events published.
func appendAndTail(t *testing.T, ts *TranscriptScanner, sub <-chan event.Event, offsets map[string]int64, path, line string) []event.Event {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	ts.tailFile(path, offsets, nil)
	var hits []event.Event
	for {
		select {
		case e := <-sub:
			if e.Kind == event.KindTranscriptHit {
				hits = append(hits, e)
			}
		default:
			return hits
		}
	}
}

// A secret in a tailed Claude transcript line yields one transcript hit that
// carries the path, the session and the rule id, never the text; the same
// (path, rule) inside the dedupe window yields nothing more.
func TestTranscriptHitCarriesPathSessionAndRuleOnly(t *testing.T) {
	secret := "synthetic-known-secret-0123456789"
	dir := filepath.Join(t.TempDir(), ".claude", "projects", "ws")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s-1.jsonl")
	line := `{"sessionId":"s-1","type":"user","timestamp":"2026-09-22T10:00:00Z","message":{"content":"use ` + secret + `"}}`

	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.TextScanner = stubTextScanner{secret: secret}
	offsets := map[string]int64{}

	hits := appendAndTail(t, ts, sub, offsets, path, line)
	if len(hits) != 1 {
		t.Fatalf("want exactly one transcript hit (entropy dropped), got %d", len(hits))
	}
	e := hits[0]
	if e.Path != path || e.SessionID != "s-1" || e.Detail != "claude:fingerprint:fp-1" {
		t.Fatalf("hit Path=%q SessionID=%q Detail=%q; want %q s-1 claude:fingerprint:fp-1", e.Path, e.SessionID, e.Detail, path)
	}
	v := reflect.ValueOf(e)
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), secret) {
			t.Fatalf("event field %s carries the secret text", v.Type().Field(i).Name)
		}
	}

	if again := appendAndTail(t, ts, sub, offsets, path, line); len(again) != 0 {
		t.Fatalf("same (path, rule) inside the dedupe window must not re-emit, got %d", len(again))
	}
}

// With no TextScanner the redact patterns still fire, in the same Detail shape.
func TestTranscriptHitRedactFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)

	// Assembled from fragments at runtime so no scannable token literal
	// appears in source (gitleaks rule curl-auth-header).
	line := "curl -H 'Authorization: " + "Bearer " + strings.Repeat("a", 32) + "'"
	hits := appendAndTail(t, ts, sub, map[string]int64{}, path, line)
	if len(hits) != 1 || !strings.HasSuffix(hits[0].Detail, ":pattern:bearer-token") {
		t.Fatalf("want one hit with Detail ending :pattern:bearer-token, got %+v", hits)
	}
}

// Detail is "<harness>:<layer>:<rule id>"; a rule id with ":" would be
// ambiguous to parse.
func TestSecretRuleIDsCarryNoColon(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"bearer-token", "jwt-token", "aws-access-key", "fp-1"}
	for _, p := range cfg.Firewall.Patterns {
		ids = append(ids, p.ID)
	}
	for _, id := range ids {
		if strings.Contains(id, ":") {
			t.Errorf("rule id %q contains ':'", id)
		}
	}
}

// Codex rollout lines the tracer consumes still get the secret scan, tagged
// with the session id from session_meta.
func TestCodexTraceLineIsSecretScanned(t *testing.T) {
	secret := "synthetic-known-secret-0123456789"
	dir := filepath.Join(t.TempDir(), "sessions", "2026", "09", "22")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rollout-2026-09-22T10-00-00-s.jsonl")
	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.TextScanner = stubTextScanner{secret: secret}
	offsets := map[string]int64{}

	appendAndTail(t, ts, sub, offsets, path, codexMetaLine)
	out := `{"timestamp":"2026-09-22T10:00:01.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_1","output":"` + secret + `"}}`
	hits := appendAndTail(t, ts, sub, offsets, path, out)
	if len(hits) != 1 || hits[0].Detail != "codex:fingerprint:fp-1" || hits[0].SessionID != "019f58e8-6230" || hits[0].Path != path {
		t.Fatalf("want one codex hit with session and path, got %+v", hits)
	}
}

// A transcript hit carries the byte offset of the line it was found on, on
// the traced (codex) path and on the plain-scan path.
func TestTranscriptHitRecordsLineOffset(t *testing.T) {
	secret := "synthetic-known-secret-0123456789"
	dir := filepath.Join(t.TempDir(), "sessions", "2026", "09", "22")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	codex := filepath.Join(dir, "rollout-2026-09-22T10-00-00-s.jsonl")
	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.TextScanner = stubTextScanner{secret: secret}
	offsets := map[string]int64{}

	appendAndTail(t, ts, sub, offsets, codex, codexMetaLine)
	plain := `{"timestamp":"2026-09-22T10:00:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[]}}`
	appendAndTail(t, ts, sub, offsets, codex, plain)
	out := `{"timestamp":"2026-09-22T10:00:02.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_1","output":"` + secret + `"}}`
	hits := appendAndTail(t, ts, sub, offsets, codex, out)
	want := int64(len(codexMetaLine) + 1 + len(plain) + 1)
	if len(hits) != 1 || hits[0].Offset != want {
		t.Fatalf("codex hit offset: got %+v, want one hit at %d", hits, want)
	}

	activity := filepath.Join(t.TempDir(), "activity.jsonl")
	first := `{"event":"noop"}`
	appendAndTail(t, ts, sub, map[string]int64{}, activity, first)
	hits = appendAndTail(t, ts, sub, map[string]int64{}, activity, "use "+secret)
	if len(hits) != 1 || hits[0].Offset != int64(len(first)+1) {
		t.Fatalf("plain-scan hit offset: got %+v, want one hit at %d", hits, len(first)+1)
	}
}

// A Codex rollout under an openclaw agent's Codex home notes that agent as
// the session's origin; one under the user's own ~/.codex notes none.
func TestCodexSessionSeenCarriesOrigin(t *testing.T) {
	root := t.TempDir()
	agent := filepath.Join(root, ".openclaw", "agents", "x", "agent", "codex-home", "sessions", "2026", "09", "22")
	own := filepath.Join(root, ".codex", "sessions", "2026", "09", "22")
	for _, d := range []string{agent, own} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	var origins []string
	ts.OnCodexSessionSeen = func(id, _, origin string, _ time.Time) {
		if id == "" {
			t.Errorf("empty session id")
		}
		origins = append(origins, origin)
	}
	offsets := map[string]int64{}

	appendAndTail(t, ts, sub, offsets, filepath.Join(agent, "rollout-2026-09-22T10-00-00-a.jsonl"), codexMetaLine)
	if len(origins) == 0 || origins[len(origins)-1] != "x (openclaw)" {
		t.Fatalf("openclaw agent rollout origins = %q, want x (openclaw)", origins)
	}
	origins = nil
	appendAndTail(t, ts, sub, offsets, filepath.Join(own, "rollout-2026-09-22T10-00-00-b.jsonl"), codexMetaLine)
	if len(origins) == 0 {
		t.Fatal("own codex rollout: session not noted")
	}
	for _, o := range origins {
		if o != "" {
			t.Fatalf("own codex rollout origin = %q, want none", o)
		}
	}
}

func TestCodexOrigin(t *testing.T) {
	for path, want := range map[string]string{
		"/Volumes/M/.openclaw/agents/quill/agent/codex-home/sessions/2026/09/24/rollout-a.jsonl": "quill (openclaw)",
		"/Users/u/.codex/sessions/2026/09/24/rollout-a.jsonl":                                    "",
		"/Users/u/custom-home/sessions/2026/09/24/rollout-a.jsonl":                               "",
		"/Users/u/rollout-a.jsonl":                                                               "",
	} {
		if got := CodexOrigin(path); got != want {
			t.Errorf("CodexOrigin(%q) = %q, want %q", path, got, want)
		}
	}
}

// patternScanner is the firewall's typed-pattern layer alone.
type patternScanner struct{ d *firewall.Detector }

func (p patternScanner) ScanText(text string) []firewall.Hit { return p.d.ScanPatterns(text) }

// A pattern hit carries the value-free reasons its value looks like a test
// value; a live-looking value beside the fixture, or alone, carries none.
func TestTranscriptHitCarriesTestSignals(t *testing.T) {
	d, err := firewall.NewDetector([]config.PatternConfig{{ID: "anthropic-key", Type: "vendor-key", Re: `sk-ant-[A-Za-z0-9_-]{24,}`}}, config.EntropyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	key := "sk-ant-" + "api03-" + "Qz7Lk2Vb9Rt4Wm1Xc8Np5Hj3Gd6Fs0Ae"
	other := "sk-ant-" + "api03-" + "Pl4Kj7Mn2Bv5Cx8Zq1Wr6Ty9Ui3Op0As"
	placeholder := "sk-ant-" + "api03-" + "your_key_here_placeholder_value"
	fixture := `{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"cat > test/memory/record.test.ts <<'EOF'\n  it(\"scrubs secrets\", () => {\n    expect(scrub(\"Key is ` + key + ` ok\")).not.toContain(\"sk-ant-\");\n"}}]}}`
	for _, tc := range []struct {
		name, line string
		want       []string
	}{
		{"fixture in a test being written", fixture, []string{"a test or example file named in the same record (record.test.ts)", "test code around it", "dummy, sample or redaction wording around it"}},
		{"a placeholder, then a live-looking key in prose", `{"type":"user","message":{"content":"template ` + placeholder + ` ` + strings.Repeat("lorem ipsum ", 30) + ` prod uses ` + other + `"}}`, nil},
		{"a live-looking key alone", `{"type":"user","message":{"content":"my key is ` + other + `"}}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := NewTranscriptScanner(bus.New(8), nil)
			ts.TextScanner = patternScanner{d}
			evs := ts.scanLine(tc.line, "/t/s.jsonl", "claude", "s-1", 0)
			if len(evs) != 1 || evs[0].Detail != "claude:pattern:anthropic-key" {
				t.Fatalf("events = %+v", evs)
			}
			if evs[0].TestSignals != strings.Join(tc.want, "; ") {
				t.Fatalf("signals = %q, want %q", evs[0].TestSignals, tc.want)
			}
			if strings.Contains(evs[0].TestSignals, "sk-ant-") {
				t.Fatalf("signals %q carry the value", evs[0].TestSignals)
			}
		})
	}
}

// tailAll writes lines to path in one append, as Claude Code writes the
// records of one API call, runs one tail pass and returns every event
// published.
func tailAll(t *testing.T, ts *TranscriptScanner, sub <-chan event.Event, path string, lines ...string) []event.Event {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts.tailFile(path, map[string]int64{}, nil)
	var evs []event.Event
	for {
		select {
		case e := <-sub:
			evs = append(evs, e)
		default:
			return evs
		}
	}
}

// Three transcript records sharing one message id (thinking, text, tool_use
// blocks of one API call, each repeating the usage) publish one model call,
// keyed by the message id and carrying the usage once.
func TestTailerPublishesOneModelCallPerMessageID(t *testing.T) {
	const id = "msg_011CfeBErVrQAEqLwcEDk6CU"
	path := filepath.Join(t.TempDir(), ".claude", "projects", "ws", "sess-1.jsonl")
	b := bus.New(64)
	sub := b.Subscribe()
	evs := tailAll(t, NewTranscriptScanner(b, nil), sub, path,
		claudeBlockRecord(id, "2026-10-02T22:11:59.088Z", `{"type":"thinking","thinking":"plan"}`, 1819),
		claudeBlockRecord(id, "2026-10-02T22:11:59.099Z", `{"type":"text","text":"Running the tests."}`, 1819),
		claudeBlockRecord(id, "2026-10-02T22:11:59.101Z", `{"type":"tool_use","id":"toolu_9","name":"Bash","input":{"command":"go test"}}`, 1819),
	)
	var calls, tools []event.Event
	for _, e := range evs {
		switch e.Kind {
		case event.KindModelCall:
			calls = append(calls, e)
		case event.KindToolCall:
			tools = append(tools, e)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("published %d model calls for one message id, want 1: %+v", len(calls), calls)
	}
	mc := calls[0]
	want := ModelCostUSD("claude-sonnet-4-5", 1000, 1819)
	if mc.CallID != id || mc.SessionID != "sess-1" || mc.TokensIn != 1000 || mc.TokensOut != 1819 || mc.CostUSD != want {
		t.Fatalf("model call = %+v, want %s in sess-1 with 1000/1819 tokens costing %v", mc, id, want)
	}
	if len(tools) != 1 || tools[0].CallID != "toolu_9" {
		t.Fatalf("tool calls = %+v, want the tool_use block's call", tools)
	}
}

// A repeat record that publishes no model call still has its text scanned,
// and the hit keeps the transcript's session.
func TestRepeatRecordSecretHitKeepsSession(t *testing.T) {
	secret := "synthetic-known-secret-0123456789"
	path := filepath.Join(t.TempDir(), ".claude", "projects", "ws", "sess-1.jsonl")
	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.TextScanner = stubTextScanner{secret: secret}
	evs := tailAll(t, ts, sub, path,
		claudeBlockRecord("msg_1", "2026-10-02T22:11:59.088Z", `{"type":"thinking","thinking":"plan"}`, 10),
		claudeBlockRecord("msg_1", "2026-10-02T22:11:59.099Z", `{"type":"text","text":"use `+secret+`"}`, 10),
	)
	var hits []event.Event
	for _, e := range evs {
		if e.Kind == event.KindTranscriptHit {
			hits = append(hits, e)
		}
	}
	if len(hits) != 1 || hits[0].SessionID != "sess-1" || hits[0].Detail != "claude:fingerprint:fp-1" {
		t.Fatalf("hits = %+v, want one claude:fingerprint:fp-1 hit in sess-1", hits)
	}
}

func TestTranscriptHookRetainsCheckpointUntilDelivery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	line := `{"type":"session_start","session_id":"hook-session","harness":"cursor","workspace":"/repo","pid":42,"ts":"2026-10-06T18:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	b.Publish(event.Event{PID: 99})
	ts := NewTranscriptScanner(b, nil)
	ts.OffsetStatePath = filepath.Join(t.TempDir(), "offsets.json")
	handshakes, produced := 0, 0
	ts.OnHandshake = func(Handshake) { handshakes++ }
	ts.OnProduce = func() { produced++ }
	offsets := map[string]int64{}
	dirty := false
	ts.tailFile(path, offsets, &dirty)
	if off, ok := offsets[path]; !ok || off != 0 || !dirty || b.Dropped() != 0 || produced != 0 {
		t.Fatalf("offsets=%v dirty=%v drops=%d produced=%d", offsets, dirty, b.Dropped(), produced)
	}
	ts.saveOffsets(offsets)
	if off, ok := ts.loadOffsets()[path]; !ok || off != 0 {
		t.Fatal("restart checkpoint skipped rejected hook")
	}
	ts.tailFile(path, offsets, &dirty)
	if handshakes != 1 {
		t.Fatal("rejected line was parsed twice")
	}
	<-sub
	dirty = false
	ts.tailFile(path, offsets, &dirty)
	got := <-sub
	if got.SessionID != "hook-session" || got.Detail != "session-start" || got.PID != 42 {
		t.Fatalf("event=%+v", got)
	}
	if offsets[path] != int64(len(line)) || !dirty || produced != 1 || handshakes != 1 {
		t.Fatal("delivery did not commit exactly once")
	}
	ts.tailFile(path, offsets, &dirty)
	if len(sub) != 0 || b.Dropped() != 0 {
		t.Fatal("duplicate or dropped hook")
	}
}

func TestTranscriptPartialDeliveryPreservesTracePairingAndSecretHit(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "projects", "ws", "sess-1.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "synthetic-known-secret-0123456789"
	line := strings.Replace(claudeAssistantLine, "go test ./...", secret, 1) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.TextScanner = stubTextScanner{secret: secret}
	seen := 0
	ts.OnSessionSeen = func(string, string, string, time.Time) { seen++ }
	offsets := map[string]int64{}
	ts.tailFile(path, offsets, nil)
	if offsets[path] != 0 || b.Dropped() != 0 {
		t.Fatal("partially delivered line checkpointed or dropped")
	}
	for _, kind := range []event.Kind{event.KindModelCall, event.KindToolCall, event.KindTranscriptHit} {
		select {
		case got := <-sub:
			if got.Kind != kind || got.SessionID != "sess-1" {
				t.Fatalf("event=%+v want kind=%v", got, kind)
			}
			if kind == event.KindModelCall && (got.TokensIn != 1000 || got.TokensOut != 50) {
				t.Fatalf("usage lost: %+v", got)
			}
		default:
			t.Fatalf("missing %v", kind)
		}
		ts.tailFile(path, offsets, nil)
	}
	if offsets[path] != int64(len(line)) || seen != 1 || len(sub) != 0 || b.Dropped() != 0 {
		t.Fatalf("offset=%d seen=%d queued=%d drops=%d", offsets[path], seen, len(sub), b.Dropped())
	}
	result := `{"type":"user","sessionId":"sess-1","timestamp":"2026-09-17T12:00:31.500Z","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","is_error":false}]}}`
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString(result + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	ts.tailFile(path, offsets, nil)
	got := <-sub
	if got.ToolStatus != "ok" || got.DurationMs != 31500 || got.CallID != "toolu_1" {
		t.Fatalf("trace state replayed: %+v", got)
	}
}

func TestTranscriptPendingDeliverySurvivesSourceRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	if err := os.WriteFile(path, []byte(`{"tool":"Bash","pid":42,"session_id":"hook-session","ts":"2026-10-06T18:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	b.Publish(event.Event{PID: 99})
	ts := NewTranscriptScanner(b, []string{filepath.Join(filepath.Dir(path), "*.jsonl")})
	ts.tailEvery = time.Millisecond
	ts.resolveEvery = time.Hour
	ts.tailFile(path, map[string]int64{}, nil)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	<-sub
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ts.Run(ctx) }()
	select {
	case got := <-sub:
		if got.SessionID != "hook-session" || got.PID != 42 {
			t.Fatalf("event=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("pending delivery was abandoned when the file disappeared")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tailer did not stop")
	}
}

// A failed save must remain dirty even if the transcript stays idle afterward.
// Otherwise a transient checkpoint fault lasts until another source changes.
func TestTranscriptCheckpointRetriesWithoutNewActivity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "activity.jsonl")
	state := filepath.Join(dir, "offsets.json")
	line := `{"tool":"Bash","session_id":"retry-session","pid":42}` + "\n"
	if err := os.Mkdir(state+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{path})
	ts.OffsetStatePath = state
	ts.tailEvery = time.Millisecond
	ts.resolveEvery = 5 * time.Millisecond
	ts.saveEvery = 10 * time.Millisecond
	writes := make(chan error, 1)
	ts.OnCheckpointWrite = func(err error) {
		select {
		case writes <- err:
		default:
		}
	}
	resolved := make(chan struct{}, 1)
	resolves := 0
	ts.ExtraTargets = func() []string {
		resolves++
		if resolves == 2 {
			resolved <- struct{}{}
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ts.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("scanner did not stop")
		}
	}()
	select {
	case <-resolved:
	case <-time.After(time.Second):
		t.Fatal("scanner did not start")
	}
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sub:
		if got.SessionID != "retry-session" {
			t.Fatalf("event=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("checkpoint fault blocked collection")
	}
	select {
	case err := <-writes:
		if err == nil {
			t.Fatal("blocked checkpoint reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("checkpoint write failure was not reported")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("blocked checkpoint unexpectedly exists: %v", err)
	}
	if err := os.Remove(state + ".tmp"); err != nil {
		t.Fatal(err)
	}
	// Restore the destination without any further source activity.
	deadline := time.After(time.Second)
	for {
		select {
		case err := <-writes:
			if err != nil {
				continue
			}
			data, err := os.ReadFile(state)
			var offsets map[string]int64
			if err != nil || json.Unmarshal(data, &offsets) != nil || offsets[path] != int64(len(line)) {
				t.Fatalf("recovery did not persist delivered offset: %s, %v", data, err)
			}
			return
		case <-deadline:
			t.Fatal("checkpoint was not retried after recovery without new activity")
		}
	}
}
