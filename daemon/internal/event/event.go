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

// Event is the single payload type on the bus. Optional fields are zero when
// not applicable to the Kind.
type Event struct {
	Kind    Kind
	TS      time.Time
	PID     int32
	ExePath string
	// File events:
	Path string
	// Conn events:
	RemoteHost string
	RemotePort int
	// Transcript/plugin events:
	Detail string // rule id or short label; NEVER a secret value
}
