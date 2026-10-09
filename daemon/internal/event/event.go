package event

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"time"
)

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
	// Payload rides on the bus into durable flag evidence. The event table
	// keeps its existing schema; the flag owns the persisted request outcome.
	Payload *model.PayloadEvidence `json:"payload,omitempty"`
	// Offset is the byte offset of the transcript line a transcript hit was
	// found on.
	Offset int64 `json:"offset,omitempty"`
	// TestSignals are a transcript hit's reasons its value looks like a test,
	// dummy or sentinel value (testvalue.Signals), joined by "; "; never the
	// value. Not in the events table: the flag's evidence keeps them.
	TestSignals string `json:"test_signals,omitempty"`
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
	// CallID is the harness's own id for the call: the tool-call id for a
	// tool_call (Claude tool_use id, Codex call_id, opencode callID), the API
	// message id for a Claude model_call. It makes the row keyed and
	// idempotent (store.PutEvent upserts on (session_id, call_id)): a tool
	// call's completion updates its start row, the per-content-block records
	// of one Claude API call are one model call, and a transcript re-read
	// cannot duplicate either. Empty for other events.
	CallID string `json:"call_id,omitempty"`
	// Record marks the event as part of the security record: it raised a
	// flag or touched a sensitive path. The store keeps record rows past
	// their kind's row budget (time retention still applies); never
	// serialized.
	Record bool `json:"-"`
	// PPID is the parent pid Endpoint Security recorded at event time (ES
	// events only). Session attribution falls back to it for a process that
	// exited before its event was resolved; never stored or serialized.
	PPID int32 `json:"-"`
	// File-open facts Endpoint Security recorded: the open flags (FREAD,
	// FWRITE), the file's st_mode, inode and birth time (unix ns). Zero when
	// unknown; never stored or serialized.
	OpenFlags int32  `json:"-"`
	FileMode  uint32 `json:"-"`
	FileIno   uint64 `json:"-"`
	FileBirth int64  `json:"-"`
}

// Open flag bits (fcntl.h FREAD, FWRITE).
const (
	OpenRead  int32 = 0x1
	OpenWrite int32 = 0x2
)

// IsDirOpen reports whether the open is known to be of a directory.
func (e Event) IsDirOpen() bool { return e.FileMode&0o170000 == 0o040000 }

// OpensForRead reports whether the open may read contents; unknown flags do.
func (e Event) OpensForRead() bool { return e.OpenFlags == 0 || e.OpenFlags&OpenRead != 0 }

// OpensForWrite reports whether the open is known to write.
func (e Event) OpensForWrite() bool { return e.OpenFlags&OpenWrite != 0 }
