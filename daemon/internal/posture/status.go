package posture

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// CoverageStatus answers "of the harnesses actually running, how many is the
// daemon seeing?" — the monitor reporting its own blindness. HarnessesSeen
// counts harnesses (agent kinds, infra excluded) with attributed activity in
// the recent window; HarnessesActive counts those with live processes.
type CoverageStatus struct {
	HarnessesActive   int                    `json:"harnesses_active"`
	HarnessesSeen     int                    `json:"harnesses_seen"`
	Harnesses         []HarnessCoverage      `json:"harnesses,omitempty"`
	Sessions          []SessionCoverage      `json:"sessions,omitempty"`
	SessionsStale     bool                   `json:"sessions_stale,omitempty"`
	SessionsTruncated bool                   `json:"sessions_truncated,omitempty"`
	Probes            []CoverageProbeReceipt `json:"probes,omitempty"`
}

type AgentSummary struct {
	PID  int32  `json:"pid"`
	Name string `json:"name"`
	// Kind is "agent" or "infra" (IDEs, local model servers). Infra processes
	// stay visible for resources and kill, but never count as agents.
	Kind      string `json:"kind,omitempty"`
	ExePath   string `json:"exe_path,omitempty"`
	CWD       string `json:"cwd,omitempty"`
	PPID      int32  `json:"ppid,omitempty"`
	RootPID   int32  `json:"root_pid,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	// LastSeenAt is the timestamp of the most recent event attributed to this
	// process (RFC3339) — the staleness signal for the agents panel.
	LastSeenAt string  `json:"last_seen_at,omitempty"`
	RSSBytes   uint64  `json:"rss_bytes,omitempty"`
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	IsOrphan   bool    `json:"is_orphan,omitempty"`

	// Durable-session identity, joined by RootPID, so a client can label a row
	// "claude · secure-agent@main" instead of a bare process cwd. Empty when no
	// session has been resolved for the tree yet.
	SessionID string `json:"session_id,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Branch    string `json:"branch,omitempty"`
	// Origin names the agent that spawned the session ("quill (openclaw)");
	// empty for the user's own sessions.
	Origin string `json:"origin,omitempty"`
}

type Status struct {
	Running      bool   `json:"running"`
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	ActiveAgents int    `json:"active_agents"`
	// InfraCount counts distinct tree ROOTS of kind=infra families (IDEs,
	// local model servers) — shared infrastructure, shown beside but never
	// inside ActiveAgents ("Agents 4 · Sessions 9 · Infra 3").
	InfraCount   int            `json:"infra_count,omitempty"`
	Agents       []AgentSummary `json:"agents"`
	Trees        []AgentTree    `json:"trees"`
	ProxyEnabled bool           `json:"proxy_enabled"`
	ProxyPort    int            `json:"proxy_port"`
	// ProxyTunneled and ProxyDecrypted count the routed CONNECTs the proxy
	// served since start: passed through unopened, and decrypted.
	ProxyTunneled     uint64 `json:"proxy_tunneled,omitempty"`
	ProxyDecrypted    uint64 `json:"proxy_decrypted,omitempty"`
	UninspectedEgress int    `json:"uninspected_egress"`
	// UninspectedInfra counts unrouted endpoints classified as known
	// CDN/cloud infrastructure (the agents' own API carriers). Reported for
	// honesty but excluded from the headline above — infra is a routing
	// coverage note, not a finding.
	UninspectedInfra int `json:"uninspected_infra"`
	// AdvisorEnabled reports whether the local triage advisor is configured
	// (opt-in) — the UIs show it so "no verdicts" is distinguishable from
	// "advisor off".
	AdvisorEnabled bool `json:"advisor_enabled"`
	// AdvisorHealth carries the advisor's live health (circuit state, last
	// error, queue depth) so "no verdicts yet" is distinguishable from
	// "model server down" — the silent pause that made advisor actions look
	// dead. Nil when unwired (unit tests, older integrations).
	AdvisorHealth *advisor.HealthSnapshot `json:"advisor_health,omitempty"`
	// TrackedProcesses is the full tagged process count (every descendant in
	// every agent tree), while ActiveAgents counts distinct tree ROOTS — the
	// number a human means by "agents running". 266 processes is not 266
	// agents; conflating them erodes trust in the headline number.
	TrackedProcesses int `json:"tracked_processes"`
	// MutedFlags counts flags suppressed by operator dispositions (mute
	// rule+host) — proof the quiet is deliberate, not a hidden silence.
	MutedFlags int `json:"muted_flags"`
	// CredentialOwnerUses counts connections judged a credential used with
	// its owner (the reader's process tree reached an org credential_owners
	// names for that file) — recorded, not flagged.
	CredentialOwnerUses int `json:"credential_owner_uses"`
	// ExpectedFlags counts connections an operator-expected read-then-connect
	// pattern covered (GET /expected) — recorded, not flagged.
	ExpectedFlags int `json:"expected_flags"`
	// FleetConfigured is true when at least one HMAC fleet webhook is set —
	// the console hides the fleet panel until then.
	FleetConfigured bool `json:"fleet_configured,omitempty"`
	// UnactedFlags24h is severity>=2 flags in the last 24h the operator has
	// not acknowledged — the console KPI, matching posture. Null when the
	// flags could not be read.
	UnactedFlags24h *int `json:"unacted_flags_24h"`
	// BusDrops counts in-process events a subscriber missed because its
	// buffer was full. Zero is healthy; growth under N-agent bursts is the
	// hot-path signal to surface.
	BusDrops             uint64 `json:"bus_drops,omitempty"`
	FileTelemetryEnabled *bool  `json:"file_telemetry_enabled,omitempty"`
	// DeltaDrops counts missed live-update deliveries before a slow subscriber
	// was disconnected. Clients reconcile from snapshots; stored evidence remains.
	DeltaDrops uint64 `json:"delta_drops,omitempty"`
	// BusDropAt records history; BusDropping reports current delivery pressure.
	BusDropAt              *time.Time                    `json:"bus_drop_at,omitempty"`
	BusDropping            bool                          `json:"bus_dropping,omitempty"`
	StorageHealth          *store.WriteHealth            `json:"storage_health,omitempty"`
	EgressProjectionHealth *store.EgressProjectionHealth `json:"egress_projection_health,omitempty"`
	HookIngestion          *store.HookIngestionSnapshot  `json:"hook_ingestion,omitempty"`
	OTLPDropped            uint64                        `json:"otlp_dropped,omitempty"`
	OTLPFailing            bool                          `json:"otlp_failing,omitempty"`

	// Coverage reports how many running harnesses the daemon is actually
	// seeing ("seeing 2 of 3 harnesses") — liveness is not coverage.
	Coverage *CoverageStatus `json:"coverage,omitempty"`

	FirewallStats map[string]firewall.RuleStat `json:"firewall_stats,omitempty"`
	// Collectors reports each supervised worker's health so a dead or abandoned
	// collector cannot appear healthy just because the daemon process is up.
	Collectors []supervise.Health `json:"collectors,omitempty"`
	// ESService carries the real state of the root LaunchDaemon that writes
	// the ES spool, when the daemon tails it. The tailer's own health proves
	// nothing about the writer; this is the probe that catches the writer
	// crash-looping while the tailer reads green. Nil when file telemetry is
	// not spool-based.
	ESService *collect.ESServiceSnapshot `json:"es_service,omitempty"`
}

// AgentTree is one session: the tagged root plus its helpers. The daemon
// emits this so the console and menubar do not regroup the flat agent list.
type AgentTree struct {
	Root       AgentSummary   `json:"root"`
	Children   []AgentSummary `json:"children"`
	RSSBytes   uint64         `json:"rss_bytes,omitempty"`
	CPUPercent float64        `json:"cpu_percent,omitempty"`
	LastSeen   string         `json:"last_seen_at,omitempty"`
}

// HarnessCoverage separates supported capabilities from recent, attributed
// activity. A timestamp is evidence for a harness, not a guarantee that every
// current session is guarded. Payload inspection is separate proxy routing.
type HarnessCoverage struct {
	Name           string `json:"name"`
	GuardSupported bool   `json:"guard_supported"`
	TraceSupported bool   `json:"trace_supported"`
	HookLastSeen   string `json:"hook_last_seen,omitempty"`
	TraceLastSeen  string `json:"trace_last_seen,omitempty"`
}

type CoveragePath struct {
	Supported bool   `json:"supported"`
	State     string `json:"state"`
	LastSeen  string `json:"last_seen,omitempty"`
	Detail    string `json:"detail"`
}

// A setup probe is intentionally absent here: manually exercising a hook
// does not demonstrate that a running agent invokes it.
type SessionCoverage struct {
	SessionID     string       `json:"session_id,omitempty"`
	Harness       string       `json:"harness"`
	Workspace     string       `json:"workspace,omitempty"`
	RootPID       int32        `json:"root_pid"`
	IdentityBasis string       `json:"identity_basis"`
	Guard         CoveragePath `json:"guard"`
	Trace         CoveragePath `json:"trace"`
	Payload       CoveragePath `json:"payload"`
}

// A receipt verifies this installed hook's manual round trip only. It never
// becomes session activity or an authorization, and restart clears it.
type CoverageProbeReceipt struct {
	Harness   string    `json:"harness"`
	HookPath  string    `json:"hook_path"`
	CheckedAt time.Time `json:"checked_at"`
	State     string    `json:"state"`
	Detail    string    `json:"detail"`
}
