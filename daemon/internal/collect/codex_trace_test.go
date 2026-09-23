package collect

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

const codexMetaLine = `{"timestamp":"2026-07-13T00:37:32.822Z","ordinal":0,"type":"session_meta","payload":{"session_id":"019f58e8-6230","id":"019f58e8-6230","cwd":"/Volumes/x/repo","originator":"Codex Desktop"}}`
const codexTokenLine = `{"timestamp":"2026-09-18T19:21:47.166Z","ordinal":79022,"type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":94510,"cached_input_tokens":94080,"output_tokens":1200}}}}`
const codexCallLine = `{"timestamp":"2026-09-18T19:21:50.000Z","type":"response_item","payload":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"shell","arguments":"{}"}}`
const codexOutputLine = `{"timestamp":"2026-09-18T19:21:52.500Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_1","output":"{}"}}`

func TestCodexTraceMetaTokensAndToolPairing(t *testing.T) {
	tr := NewCodexTracer()

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
		tr := NewCodexTracer()
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
	tr := NewCodexTracer()
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
	tr := NewCodexTracer()
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
