package collect

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

const codexMetaLine = `{"timestamp":"2026-07-13T00:37:32.822Z","ordinal":0,"type":"session_meta","payload":{"session_id":"019f58e8-6230","id":"019f58e8-6230","cwd":"/Volumes/x/repo","originator":"Codex Desktop"}}`
const codexTokenLine = `{"timestamp":"2026-09-18T19:21:47.166Z","ordinal":79022,"type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":94510,"cached_input_tokens":94080,"output_tokens":1200}}}}`
const codexCallLine = `{"timestamp":"2026-09-18T19:21:50.000Z","type":"response_item","payload":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"shell","arguments":"{}"}}`
const codexOutputLine = `{"timestamp":"2026-09-18T19:21:52.500Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_1","output":"{}"}}`

func TestCodexTraceMetaTokensAndToolPairing(t *testing.T) {
	tr := NewCodexTracer("")

	// session_meta teaches the tracer the session id + workspace.
	if _, ok := tr.ParseLine(codexMetaLine); !ok {
		t.Fatal("session_meta not recognized")
	}
	id, cwd := tr.Session()
	if id != "019f58e8-6230" || cwd != "/Volumes/x/repo" {
		t.Fatalf("session = %q %q", id, cwd)
	}

	// token_count → model_call with the per-call delta; model unknown → no cost.
	evs, ok := tr.ParseLine(codexTokenLine)
	if !ok || len(evs) != 1 {
		t.Fatalf("token_count evs = %+v", evs)
	}
	mc := evs[0]
	if mc.Kind != event.KindModelCall || mc.TokensIn != 94510 || mc.TokensOut != 1200 {
		t.Fatalf("model_call = %+v", mc)
	}
	if mc.Model != "" || mc.CostUSD != 0 {
		t.Fatalf("codex model must stay unknown (cost 0), got %q $%v", mc.Model, mc.CostUSD)
	}
	if mc.SessionID != "019f58e8-6230" {
		t.Fatalf("session = %q", mc.SessionID)
	}

	// function_call → running; function_call_output pairs by call_id.
	evs, _ = tr.ParseLine(codexCallLine)
	if len(evs) != 1 || evs[0].ToolName != "shell" || evs[0].ToolStatus != "running" {
		t.Fatalf("function_call = %+v", evs)
	}
	evs, _ = tr.ParseLine(codexOutputLine)
	if len(evs) != 1 || evs[0].ToolStatus != "ok" || evs[0].DurationMs != 2500 {
		t.Fatalf("paired tool_call = %+v", evs)
	}
	if evs[0].TS.Format("15:04:05") != "19:21:50" {
		t.Fatalf("ts = %v, want the call start", evs[0].TS)
	}
}

const codexSettingsLine = `{"timestamp":"2026-09-18T19:21:40.000Z","type":"event_msg","payload":{"type":"thread_settings_applied","thread_id":"019f58e8-6230","thread_settings":{"model":"m-test","model_provider_id":"custom","cwd":"/Volumes/x/repo"}}}`

// thread_settings_applied names the model: later model_calls carry it, priced
// only when a price table knows the id.
func TestCodexTraceAttributesModelFromThreadSettings(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	parse := func() event.Event {
		t.Helper()
		tr := NewCodexTracer("")
		tr.ParseLine(codexMetaLine)
		// The settings line emits nothing and stays eligible for the
		// caller's redaction scan (ok=false).
		if evs, ok := tr.ParseLine(codexSettingsLine); ok || len(evs) != 0 {
			t.Fatalf("settings line = %+v ok=%v, want no events and ok=false", evs, ok)
		}
		if id, provider := tr.Model(); id != "m-test" || provider != "custom" {
			t.Fatalf("tracer model = %q %q", id, provider)
		}
		evs, ok := tr.ParseLine(codexTokenLine)
		if !ok || len(evs) != 1 || evs[0].Kind != event.KindModelCall {
			t.Fatalf("token_count evs = %+v", evs)
		}
		return evs[0]
	}

	mc := parse()
	if mc.Model != "m-test" || mc.CostUSD != 0 {
		t.Fatalf("unknown id must be attributed and unpriced, got %q $%v", mc.Model, mc.CostUSD)
	}

	SetUserPrices(map[string][2]float64{"m-test": {1, 2}})
	mc = parse()
	want := (float64(94510)*1 + float64(1200)*2) / 1e6
	if mc.Model != "m-test" || mc.CostUSD != want {
		t.Fatalf("priced call = %q $%v, want $%v", mc.Model, mc.CostUSD, want)
	}
}

// A rollout without the settings line keeps model_calls model-less and cost 0,
// whatever the price tables hold.
func TestCodexTraceWithoutThreadSettingsStaysUnpriced(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	SetUserPrices(map[string][2]float64{"m-test": {1, 2}})
	tr := NewCodexTracer("")
	tr.ParseLine(codexMetaLine)
	evs, ok := tr.ParseLine(codexTokenLine)
	if !ok || len(evs) != 1 {
		t.Fatalf("token_count evs = %+v", evs)
	}
	if evs[0].Model != "" || evs[0].CostUSD != 0 {
		t.Fatalf("no settings line: got %q $%v, want empty model and cost 0", evs[0].Model, evs[0].CostUSD)
	}
}

func TestCodexTraceRejectsForeign(t *testing.T) {
	tr := NewCodexTracer("")
	if _, ok := tr.ParseLine(`{"tool":"Read","pid":1}`); ok {
		t.Fatal("plugin activity line must not parse as a codex record")
	}
	if _, ok := tr.ParseLine(`{"type":"user","message":{"role":"user"}}`); ok {
		t.Fatal("non-rollout record must not parse")
	}
}

func TestIsCodexRolloutPath(t *testing.T) {
	if !IsCodexRolloutPath("/Users/x/.codex/sessions/2026/07/12/rollout-2026-07-12T20-37-32-abc.jsonl") {
		t.Fatal("rollout not recognized")
	}
	if IsCodexRolloutPath("/Users/x/.claude/projects/-r/abc.jsonl") {
		t.Fatal("claude transcript misclassified as codex rollout")
	}
}

// Real rollout shapes (codex 0.146): session_meta names the provider but no
// model; turn_context (one per turn) names the model; no settings line.
const codexRealMetaLine = `{"timestamp":"2026-09-23T02:30:21.000Z","type":"session_meta","payload":{"session_id":"019f-sol","id":"019f-sol","timestamp":"2026-09-23T02:30:21.000Z","cwd":"/Volumes/x/repo","originator":"codex_exec","cli_version":"0.146.0","source":"exec","model_provider":"custom","base_instructions":{"text":"x"}}}`

func codexTurnContextLine(model string) string {
	return `{"timestamp":"2026-09-23T02:30:22.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/Volumes/x/repo","approval_policy":"never","model":"` + model + `","effort":"high","summary":"auto"}}`
}

func codexModelCall(t *testing.T, tr *CodexTracer) event.Event {
	t.Helper()
	evs, ok := tr.ParseLine(codexTokenLine)
	if !ok || len(evs) != 1 || evs[0].Kind != event.KindModelCall {
		t.Fatalf("token_count evs = %+v ok=%v", evs, ok)
	}
	return evs[0]
}

// turn_context names the model and session_meta the provider when no
// thread_settings_applied line exists.
func TestCodexTraceModelFromTurnContext(t *testing.T) {
	tr := NewCodexTracer("")
	tr.ParseLine(codexRealMetaLine)
	if evs, ok := tr.ParseLine(codexTurnContextLine("gpt-5.6-sol")); ok || len(evs) != 0 {
		t.Fatalf("turn_context = %+v ok=%v, want no events and ok=false (redaction scan kept)", evs, ok)
	}
	mc := codexModelCall(t, tr)
	if mc.Model != "gpt-5.6-sol" || mc.Provider != "custom" || mc.SessionID != "019f-sol" {
		t.Fatalf("model_call = model %q provider %q session %q, want gpt-5.6-sol/custom/019f-sol", mc.Model, mc.Provider, mc.SessionID)
	}
}

// thread_settings_applied wins over turn_context, whichever comes first.
func TestCodexTraceThreadSettingsWinsOverTurnContext(t *testing.T) {
	for name, lines := range map[string][]string{
		"settings first": {codexRealMetaLine, codexSettingsLine, codexTurnContextLine("gpt-5.6-sol")},
		"context first":  {codexRealMetaLine, codexTurnContextLine("gpt-5.6-sol"), codexSettingsLine},
	} {
		tr := NewCodexTracer("")
		for _, l := range lines {
			tr.ParseLine(l)
		}
		if mc := codexModelCall(t, tr); mc.Model != "m-test" || mc.Provider != "custom" {
			t.Errorf("%s: model %q provider %q, want m-test/custom", name, mc.Model, mc.Provider)
		}
	}
}

// A later turn_context switches the model for the calls after it.
func TestCodexTraceTurnContextModelChange(t *testing.T) {
	tr := NewCodexTracer("")
	tr.ParseLine(codexRealMetaLine)
	tr.ParseLine(codexTurnContextLine("gpt-5.6-sol"))
	if mc := codexModelCall(t, tr); mc.Model != "gpt-5.6-sol" {
		t.Fatalf("first call model %q", mc.Model)
	}
	tr.ParseLine(codexTurnContextLine("gpt-5.6-terra"))
	if mc := codexModelCall(t, tr); mc.Model != "gpt-5.6-terra" {
		t.Fatalf("after the switch model %q, want gpt-5.6-terra", mc.Model)
	}
}

// A daemon restart resumes a rollout from its persisted offset: the tracer
// must still learn the session and model from the file head.
func TestCodexResumeFromOffsetPrimesSessionAndModel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sessions", "2026", "09", "23")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "rollout-2026-09-23T02-30-21-019f-sol.jsonl")
	head := codexRealMetaLine + "\n" + codexTurnContextLine("gpt-5.6-sol") + "\n"
	if err := os.WriteFile(p, []byte(head+codexTokenLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, nil)
	ts.tailFile(p, map[string]int64{p: int64(len(head))}, nil)
	for {
		select {
		case e := <-sub:
			if e.Kind != event.KindModelCall {
				continue
			}
			if e.Model != "gpt-5.6-sol" || e.Provider != "custom" || e.SessionID != "019f-sol" {
				t.Fatalf("resumed model_call = model %q provider %q session %q", e.Model, e.Provider, e.SessionID)
			}
			return
		default:
			t.Fatal("resumed tail published no model_call")
		}
	}
}

// A token_count line on a ChatGPT-plan login carries rate_limits with a
// plan_type: its model call is billed to "chatgpt" (class plan) and the
// home's headroom snapshot is recorded; a line without rate_limits keeps the
// rollout's provider.
const codexPlanTokenLine = `{"timestamp":"2026-09-24T10:00:00.000Z","type":"event_msg","payload":{"type":"token_count",` +
	`"info":{"last_token_usage":{"input_tokens":1000,"cached_input_tokens":0,"output_tokens":100}},` +
	`"rate_limits":{"limit_id":"codex","limit_name":null,"primary":{"used_percent":52.0,"window_minutes":10080,"resets_at":1790692238},` +
	`"secondary":{"used_percent":7.5,"window_minutes":300,"resets_at":1790600000},"credits":{"has_credits":false,"unlimited":false,"balance":"0"},` +
	`"individual_limit":null,"spend_control_reached":null,"plan_type":"pro","rate_limit_reached_type":null}}}`

func TestCodexTracePlanLoginBillsChatGPT(t *testing.T) {
	path := "/Users/dev/.codex/sessions/2026/09/24/rollout-2026-09-24T10-00-00-plan.jsonl"
	tr := NewCodexTracer(path)
	tr.ParseLine(`{"timestamp":"2026-09-24T09:59:00.000Z","type":"session_meta","payload":{"session_id":"s-plan","cwd":"/r","model_provider":"openai"}}`)
	tr.ParseLine(`{"timestamp":"2026-09-24T09:59:01.000Z","type":"turn_context","payload":{"model":"gpt-5.6-sol"}}`)

	evs, ok := tr.ParseLine(codexPlanTokenLine)
	if !ok || len(evs) != 1 {
		t.Fatalf("plan token_count evs = %+v", evs)
	}
	if mc := evs[0]; mc.Provider != "chatgpt" || mc.Model != "gpt-5.6-sol" || mc.CostUSD != 0 {
		t.Fatalf("plan model_call = provider %q model %q cost %v", mc.Provider, mc.Model, mc.CostUSD)
	}
	if c := Classify(evs[0].Model, evs[0].Provider); c != ClassPlan {
		t.Fatalf("class = %q, want plan", c)
	}

	var got *PlanSnapshot
	for _, p := range Plans() {
		if p.Home == "codex" && p.SeenAt.Equal(time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)) {
			got = &p
		}
	}
	if got == nil {
		t.Fatalf("no codex snapshot recorded: %+v", Plans())
	}
	want := []PlanWindow{
		{WindowMinutes: 10080, UsedPercent: 52, ResetsAt: "2026-09-29T14:30:38Z"},
		{WindowMinutes: 300, UsedPercent: 7.5, ResetsAt: "2026-09-28T12:53:20Z"},
	}
	if got.Harness != "codex" || got.PlanType != "pro" || got.LimitID != "codex" || got.Unlimited || !slices.Equal(got.Windows, want) {
		t.Fatalf("snapshot = %+v", *got)
	}

	// API-key login: no rate_limits, the rollout's provider stays.
	evs, _ = tr.ParseLine(strings.Replace(codexTokenLine, "2026-09-18", "2026-09-24", 1))
	if len(evs) != 1 || evs[0].Provider != "openai" {
		t.Fatalf("no rate_limits: provider = %+v, want openai", evs)
	}
	if c := Classify("gpt-5.6-sol", "chatgpt"); c != ClassPlan {
		t.Fatalf(`Classify("gpt-5.6-sol","chatgpt") = %q, want plan`, c)
	}

	// A window with no resets_at serves "" (never the epoch); info null
	// (a rate-limits-only line) still records the snapshot.
	agent := NewCodexTracer("/Volumes/x/.openclaw/agents/scout/agent/codex-home/sessions/2026/09/24/rollout-s.jsonl")
	agent.ParseLine(`{"timestamp":"2026-09-24T11:00:00.000Z","type":"event_msg","payload":{"type":"token_count","info":null,` +
		`"rate_limits":{"plan_type":"plus","limit_id":"codex","primary":{"used_percent":3,"window_minutes":300},"secondary":null}}}`)
	for _, p := range Plans() {
		if p.Home == "scout (openclaw)" && (p.PlanType != "plus" || len(p.Windows) != 1 || p.Windows[0].ResetsAt != "" || p.Windows[0].WindowMinutes != 300) {
			t.Fatalf("scout snapshot = %+v", p)
		}
	}
	if !slices.ContainsFunc(Plans(), func(p PlanSnapshot) bool { return p.Home == "scout (openclaw)" }) {
		t.Fatalf("no scout snapshot: %+v", Plans())
	}
}

func TestCodexHomeLabel(t *testing.T) {
	for path, want := range map[string]string{
		"/Users/dev/.codex/sessions/2026/09/24/rollout-a.jsonl":                                      "codex",
		"/Volumes/MIRZA/.openclaw/agents/scout/agent/codex-home/sessions/2026/09/24/rollout-b.jsonl": "scout (openclaw)",
		"/srv/ci/codex-runner/sessions/2026/09/24/rollout-c.jsonl":                                   "codex-runner",
		"/Users/dev/notes/rollout-d.jsonl":                                                           "",
	} {
		if got := CodexHomeLabel(path); got != want {
			t.Errorf("CodexHomeLabel(%q) = %q, want %q", path, got, want)
		}
	}
}

// The registry keeps the newest snapshot per home by seen_at: an older line
// (a backfilled rollout) never replaces a newer one. Two homes sharing a
// label (e.g. two ".codex" dirs) are both served, keyed apart by home_path.
func TestRecordPlanKeepsNewestPerHome(t *testing.T) {
	home := "/tmp/registry-test-home"
	home2 := home + "-2"
	t0 := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	snap := func(pct float64, at time.Time) PlanSnapshot {
		return PlanSnapshot{Harness: "codex", Home: "registry-test", PlanType: "pro",
			Windows: []PlanWindow{{WindowMinutes: 300, UsedPercent: pct}}, SeenAt: at}
	}
	byPath := func(path string) (PlanSnapshot, bool) {
		for _, p := range Plans() {
			if p.HomePath == path {
				return p, true
			}
		}
		return PlanSnapshot{}, false
	}

	RecordPlan(home, snap(10, t0))
	RecordPlan(home, snap(5, t0.Add(-time.Hour))) // older: must not replace
	RecordPlan(home2, snap(90, t0.Add(-2*time.Hour)))

	p1, ok := byPath(home)
	if !ok || p1.Windows[0].UsedPercent != 10 {
		t.Fatalf("home snapshot after an older line: %+v (ok=%v)", p1, ok)
	}
	p2, ok := byPath(home2)
	if !ok || p2.Windows[0].UsedPercent != 90 {
		t.Fatalf("home2 snapshot: %+v (ok=%v)", p2, ok)
	}
	if p1.HomePath == p2.HomePath || p1.Home != p2.Home {
		t.Fatalf("expected a shared label with distinct home_path, got %+v and %+v", p1, p2)
	}

	RecordPlan(home, snap(20, t0.Add(time.Minute)))
	p1, ok = byPath(home)
	if !ok || !p1.SeenAt.Equal(t0.Add(time.Minute)) || p1.Windows[0].UsedPercent != 20 {
		t.Fatalf("newer line not kept: %+v (ok=%v)", p1, ok)
	}

	RecordPlan(home, snap(1, t0)) // older than the line just kept: must not replace
	p1, ok = byPath(home)
	if !ok || p1.Windows[0].UsedPercent != 20 {
		t.Fatalf("an older line replaced the newest: %+v (ok=%v)", p1, ok)
	}
}
