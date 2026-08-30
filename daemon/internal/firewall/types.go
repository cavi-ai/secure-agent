// Package firewall detects secret leaks in agent-originated egress payloads.
package firewall

type Layer int

const (
	LayerFingerprint Layer = iota // L1: matches a registered known secret
	LayerPattern                  // L2: matches a typed secret pattern
	LayerEntropy                  // L3: high-entropy heuristic
)

type Field int

const (
	FieldAuthHeader  Field = iota // the vendor's expected auth header
	FieldOtherHeader              // any other request header
	FieldQuery                    // URL query string
	FieldBody                     // request body
)

// Secret type tags (used for context rules and reporting; never carry a value).
const (
	TypeVendorKey  = "vendor-key"
	TypeCloudKey   = "cloud-key"
	TypePrivateKey = "private-key"
	TypeEnvValue   = "env-value"
	TypeUnknown    = "unknown"
)

type Hit struct {
	RuleID     string // pattern id or fingerprint id
	SecretType string // one of the Type* consts
	Layer      Layer
	Confidence float64 // 0..1
}

type VerdictKind int

const (
	VerdictLegit   VerdictKind = iota // expected credential use; never a leak
	VerdictSuspect                    // possible, monitor-only
	VerdictLeak                       // a real leak
)

type Mode int

const (
	ModeMonitor Mode = iota
	ModeBlock
)

type Action int

const (
	ActionAllow      Action = iota
	ActionWouldBlock        // leak on a monitor-mode rule
	ActionBlock             // leak on a block-mode rule
)

type Verdict struct {
	Kind   VerdictKind
	Mode   Mode
	Action Action
}

type RequestCtx struct {
	Agent string
	Host  string
	Field Field
}

type Finding struct {
	Hit     Hit
	Ctx     RequestCtx
	Verdict Verdict
}

type Decision struct {
	Action   Action
	Findings []Finding
}

// ParseMode maps a config string to a Mode, defaulting to ModeMonitor for any
// unknown or empty value so a typo can never silently enable blocking.
func ParseMode(s string) Mode {
	if s == "block" {
		return ModeBlock
	}
	return ModeMonitor
}

// String is the canonical config/API spelling of a Mode.
func (m Mode) String() string {
	if m == ModeBlock {
		return "block"
	}
	return "monitor"
}
