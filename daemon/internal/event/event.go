package event

import "time"

type Kind int

const (
	KindFileOpen Kind = iota
	KindFileWrite
	KindFileDelete
	KindExec
	KindTCCModify
	KindConnOpen
	KindConnClose
	KindTranscriptHit // secret pattern seen in transcript/plugin log
	KindPluginAction  // harness tool-use reported by the plugin
	KindProxyHit      // payload inspection match (secret leak or prompt injection in proxy stream)
	KindGuardPrompt   // a directory-guard prompt was enqueued (UI should refetch /guard/pending)
	KindGuardResolved // a guard prompt was resolved (UI should refetch pending + rules)
	// Trace model (P2): agent-semantic events parsed from harness transcripts.
	// These carry no content — only tool names, durations, models, tokens.
	KindToolCall  // a tool_use → tool_result pair (or unpaired start)
	KindTurn      // a user→assistant turn boundary
	KindModelCall // one model API call with usage
)

func (k Kind) String() string {
	switch k {
	case KindFileOpen:
		return "file-open"
	case KindFileWrite:
		return "file-write"
	case KindFileDelete:
		return "file-delete"
	case KindExec:
		return "exec"
	case KindTCCModify:
		return "tcc-modify"
	case KindConnOpen:
		return "conn-open"
	case KindConnClose:
		return "conn-close"
	case KindTranscriptHit:
		return "transcript-hit"
	case KindPluginAction:
		return "plugin-action"
	case KindProxyHit:
		return "proxy-hit"
	case KindGuardPrompt:
		return "guard-prompt"
	case KindGuardResolved:
		return "guard-resolved"
	case KindToolCall:
		return "tool-call"
	case KindTurn:
		return "turn"
	case KindModelCall:
		return "model-call"
	default:
		return "unknown"
	}
}

// Event is the single payload type on the bus. Optional fields are zero when
// not applicable to the Kind. JSON tags match the console's field names (the
// /events endpoint is the only JSON consumer).
type Event struct {
	Kind    Kind      `json:"kind"`
	TS      time.Time `json:"ts"`
	PID     int32     `json:"pid"`
	ExePath string    `json:"exe_path,omitempty"`
	// SessionID identifies the harness session that produced the event, so
	// evidence chains survive PID reuse. Empty for OS-level events the hooks
	// did not stamp.
	SessionID string `json:"session_id,omitempty"`
	// File events:
	Path string `json:"path,omitempty"`
	// Conn events:
	RemoteHost string `json:"remote_host,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	// Transcript/plugin events:
	Detail string `json:"detail,omitempty"` // rule id or short label; NEVER a secret value
	// Offset is the byte offset of the transcript line a transcript hit was
	// found on.
	Offset int64 `json:"offset,omitempty"`
	// Trace events (KindToolCall/KindTurn/KindModelCall):
	ToolName   string  `json:"tool,omitempty"`        // tool_call: tool name
	ToolStatus string  `json:"tool_status,omitempty"` // tool_call: ok | error | running
	DurationMs int64   `json:"duration_ms,omitempty"` // tool_call: start→result
	Model      string  `json:"model,omitempty"`       // model_call: model id
	Provider   string  `json:"provider,omitempty"`    // model_call: provider id as the harness names it (opencode providerID, codex model_provider)
	TokensIn   int64   `json:"tokens_in,omitempty"`   // model_call: input + cache-creation tokens
	TokensOut  int64   `json:"tokens_out,omitempty"`  // model_call: output tokens
	CostUSD    float64 `json:"cost_usd,omitempty"`    // model_call: approximate, from the pricing table (0 = unknown model)
	// PriceClass is a model_call's price class (priced, plan, local,
	// unknown-model, unpriced-model), stamped on the rows the API serves;
	// never stored.
	PriceClass string `json:"price_class,omitempty"`
	// CallID is the harness's own tool-call id (Claude tool_use id, Codex
	// call_id, opencode callID). For a tool_call it makes the row keyed and
	// idempotent: the start inserts, the completion updates the SAME row
	// (store.PutEvent upserts on (session_id, call_id)), and a transcript
	// re-read cannot duplicate a call. Empty for non-tool events.
	CallID string `json:"call_id,omitempty"`
	// Record marks the event as part of the security record: it raised a
	// flag or touched a sensitive path. The store keeps record rows past
	// their kind's row budget (time retention still applies); never
	// serialized.
	Record bool `json:"-"`
}
