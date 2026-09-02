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
}
