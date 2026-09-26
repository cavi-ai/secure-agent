package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentask"
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
	"golang.org/x/sys/unix"
)

type Killer interface {
	Kill(pid int32) error
}

// CoverageStatus answers "of the harnesses actually running, how many is the
// daemon seeing?" — the monitor reporting its own blindness. HarnessesSeen
// counts harnesses (agent kinds, infra excluded) with attributed activity in
// the recent window; HarnessesActive counts those with live processes.
type CoverageStatus struct {
	HarnessesActive int `json:"harnesses_active"`
	HarnessesSeen   int `json:"harnesses_seen"`
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
	InfraCount        int            `json:"infra_count,omitempty"`
	Agents            []AgentSummary `json:"agents"`
	Trees             []AgentTree    `json:"trees"`
	ProxyEnabled      bool           `json:"proxy_enabled"`
	ProxyPort         int            `json:"proxy_port"`
	UninspectedEgress int            `json:"uninspected_egress"`
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
	// FleetConfigured is true when at least one HMAC fleet webhook is set —
	// the console hides the fleet panel until then.
	FleetConfigured bool `json:"fleet_configured,omitempty"`
	// UnactedFlags24h is severity>=2 flags in the last 24h the operator has
	// not acknowledged — the console KPI, matching posture.
	UnactedFlags24h int `json:"unacted_flags_24h"`
	// BusDrops counts in-process events a subscriber missed because its
	// buffer was full. Zero is healthy; growth under N-agent bursts is the
	// hot-path signal to surface.
	BusDrops uint64 `json:"bus_drops,omitempty"`

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

type StatusFunc func() Status

type API struct {
	socketPath       string
	store            *store.Store
	killer           Killer
	statusFn         StatusFunc
	hermes           func() collect.HermesStatus
	worktrees        *worktreehunter.Hunter
	worktreeAdvisor  func(model.WorktreeAdviceRequest) bool
	clutter          *clutter.Clutter
	asker            *agentask.Asker
	sysAgent         *sysagent.Agent
	projectAdvisor   func(model.ProjectCleanupRequest) bool
	resources        func() resource.Snapshot
	resourceControl  *resource.Controller
	resourcePolicy   func(config.ResourceControlConfig) error
	resourcePolicyMu sync.Mutex

	// plan connects /advisor/plan to the current advisor (plan.go).
	plan *PlanFuncs

	// NoAgent enforcement and the file actions (files.go, tcppeer.go).
	isAgentPID   func(pid int32) bool
	tcpClientPID func(remoteAddr string) (int32, error)
	openPath     func(args ...string) error

	fwEngine      *firewall.Engine
	fwModes       *firewall.ModeStore
	fwReload      func() error
	fwIngest      func() ([]string, error)
	fwSources     *firewall.SourceStore
	fwBaseSources []string

	guardBroker *guard.Broker

	correlator   *correlate.Correlator
	allowlist    *correlate.AllowlistStore
	mutes        *correlate.MuteStore
	notifyRules  *correlate.NotifyRuleStore
	notifyScopes *correlate.NotifyScopeStore
	retriage     *RetriageFuncs
	hostAssess   *HostAssessFuncs
	guardAdvisor func(model.GuardAssessmentRequest)
	guardSeq     uint64

	peerRole   *peers
	peerChk    PeerChecker
	agentPIDs  func() map[int32]struct{}
	fleetSinks GuardEventSink
	// fleetConfigured mirrors len(cfg.Fleet.Webhooks) > 0 so /fleet can tell
	// the console whether a collector exists at all.
	fleetConfigured bool

	publishEvent func(event.Event)
	busDrops     func() uint64

	// deltas is the typed state-change fan-out the SSE stream serves.
	// lastPosture dedupes posture deltas (state + item count).
	deltaHub         *DeltaHub
	lastPostureMu    sync.Mutex
	lastPostureState string
	lastPostureCount int

	// costs caches /costs reports, saved in the store; unpriced caches
	// /costs/unpriced reports in memory (costcache.go).
	costs    costCache[store.CostReport]
	unpriced costCache[unpricedCostReport]
}

// GuardEventSink receives guard decisions (allow/deny) for downstream
// delivery. Modeled on fleet.Publisher to avoid an import cycle.
type GuardEventSink interface {
	PublishGuardDecision(decision map[string]any)
}

// FirewallControl bundles the runtime firewall controls the API exposes.
type FirewallControl struct {
	Engine      *firewall.Engine
	Modes       *firewall.ModeStore
	Reload      func() error             // re-apply persisted fingerprints
	Ingest      func() ([]string, error) // scan sources, register fingerprints, return labels
	Sources     *firewall.SourceStore    // user-added ingest sources
	BaseSources []string                 // config-defined ingest sources (read-only)
}

// RetriageFuncs look up a flag by ID and enqueue it for a fresh advisor
// verdict. The enqueue is idempotent (advisor-side cooldown); queued=false
// means "already in flight or recent" — the UI treats that as success.
type RetriageFuncs struct {
	LookupFlag func(flagID string) (model.Flag, bool)
	Enqueue    func(model.Flag) bool
}

// HostAssessFuncs look up a stored advisor verdict for an agent+host and
// enqueue an on-demand legitimacy assessment. GetVerdict returns the
// stored verdict when one exists; Enqueue queues one (idempotent). Lookup
// is separate so the console can render a cached verdict immediately while
// a fresh one is queued.
type HostAssessFuncs struct {
	GetVerdict func(agent, host string) (model.AdvisorVerdict, bool)
	Enqueue    func(agent, host string) bool
}

// Deps is the API's complete dependency set, resolved once at composition.
// It replaces the twenty optional setters: every field is read in New, so
// wiring a component is one struct literal and a missing component is visible
// at the call site instead of a nil check at serve time.
// Optional fields may be left zero — the handlers degrade to their documented
// "not enabled" response.
type Deps struct {
	SocketPath string
	Store      *store.Store
	Killer     Killer
	Status     StatusFunc

	// Resources / control (optional).
	Resources             func() resource.Snapshot
	ResourceControl       *resource.Controller
	ResourcePolicyUpdater func(config.ResourceControlConfig) error

	// Firewall (optional).
	Firewall FirewallControl

	// Directory guard (optional).
	Guard *guard.Broker

	// Correlator-derived stores (optional).
	Correlator   *correlate.Correlator
	Allowlist    *correlate.AllowlistStore
	Mutes        *correlate.MuteStore
	NotifyRules  *correlate.NotifyRuleStore
	NotifyScopes *correlate.NotifyScopeStore

	// Advisor hooks (optional).
	Retriage   *RetriageFuncs
	HostAssess *HostAssessFuncs
	Plan       *PlanFuncs

	// GuardAdvisor, when set, is offered each newly blocked guard prompt for an
	// advisory recommendation. NEVER resolves the prompt — the human decides.
	GuardAdvisor func(model.GuardAssessmentRequest)

	// Peers (optional). An empty Checker leaves the API ungated.
	PeerChecker PeerChecker
	AgentPIDs   func() map[int32]struct{}
	UIPID       int32
	// IsAgentPID reports whether pid belongs to an agent family, walking its
	// ancestry live. NoAgent routes refuse such peers; unwired, the console
	// listener refuses every NoAgent request.
	IsAgentPID func(pid int32) bool

	// Fleet + telemetry (optional).
	FleetSink       GuardEventSink
	FleetConfigured bool
	BusDrops        func() uint64
	PublishEvent    func(event.Event)
	DeltaHub        *DeltaHub

	// Hermes reports the Hermes Agent collector's state for /doctor
	// (optional; unwired reads "not wired").
	Hermes func() collect.HermesStatus

	// Worktrees is the worktree hunter behind /worktrees (optional; unwired
	// answers 503).
	Worktrees *worktreehunter.Hunter
	// Clutter is the cleanup inventory behind /cleanup (optional; unwired
	// answers 503).
	Clutter *clutter.Clutter
	// Asker resumes a worktree's owning agent for /worktrees/ask (optional).
	Asker *agentask.Asker
	// SysAgent is the system agent behind /agent/* (optional; unwired
	// answers 503).
	SysAgent *sysagent.Agent
	// ProjectAdvisor queues a project for a cleanup plan and reports
	// whether it was queued (optional).
	ProjectAdvisor func(model.ProjectCleanupRequest) bool
	// WorktreeAdvisor, when set, queues a worktree for an advisory note and
	// reports whether it was queued (false: advisor off or queue full).
	WorktreeAdvisor func(model.WorktreeAdviceRequest) bool
}

// New builds the API from its resolved dependencies.
func New(d Deps) *API {
	a := &API{
		socketPath:      d.SocketPath,
		store:           d.Store,
		killer:          d.Killer,
		statusFn:        d.Status,
		hermes:          d.Hermes,
		worktrees:       d.Worktrees,
		worktreeAdvisor: d.WorktreeAdvisor,
		clutter:         d.Clutter,
		asker:           d.Asker,
		sysAgent:        d.SysAgent,
		projectAdvisor:  d.ProjectAdvisor,
		resources:       d.Resources,
		resourceControl: d.ResourceControl,
		resourcePolicy:  d.ResourcePolicyUpdater,
		fwEngine:        d.Firewall.Engine,
		fwModes:         d.Firewall.Modes,
		fwReload:        d.Firewall.Reload,
		fwIngest:        d.Firewall.Ingest,
		fwSources:       d.Firewall.Sources,
		fwBaseSources:   d.Firewall.BaseSources,
		guardBroker:     d.Guard,
		correlator:      d.Correlator,
		allowlist:       d.Allowlist,
		mutes:           d.Mutes,
		notifyRules:     d.NotifyRules,
		notifyScopes:    d.NotifyScopes,
		retriage:        d.Retriage,
		hostAssess:      d.HostAssess,
		guardAdvisor:    d.GuardAdvisor,
		agentPIDs:       d.AgentPIDs,
		fleetSinks:      d.FleetSink,
		fleetConfigured: d.FleetConfigured,
		busDrops:        d.BusDrops,
		publishEvent:    d.PublishEvent,
		deltaHub:        d.DeltaHub,
		isAgentPID:      d.IsAgentPID,
		plan:            d.Plan,
		tcpClientPID:    TCPClientPID,
		openPath:        openWithSystem,
	}
	a.peerChk = d.PeerChecker
	if d.PeerChecker != nil {
		a.peerRole = &peers{OwnerUID: os.Getuid(), UIPID: d.UIPID, AgentPIDs: d.AgentPIDs}
	}
	if d.Store != nil {
		a.costs.st, a.costs.saveAs = d.Store, costsCacheName
	}
	return a
}

// handleAdvisorAssessHost answers "what is this endpoint, and should I trust
// it?" for one uninspected agent+host pair: the stored advisor verdict if one
// exists, otherwise it queues an assessment. This is the functionality that
// turned a wall of raw IPs into decisions — the operator no longer has to
// know what 160.79.104.10 is.
func (a *API) handleAdvisorAssessHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.hostAssess == nil {
		http.Error(w, "advisor not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Agent string `json:"agent"`
		Host  string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, `Invalid payload: {"agent","host"}`, http.StatusBadRequest)
		return
	}
	resp := map[string]any{"status": "ok", "queued": false}
	if a.hostAssess.GetVerdict != nil {
		if v, ok := a.hostAssess.GetVerdict(req.Agent, req.Host); ok {
			resp["verdict"] = v
		}
	}
	if a.hostAssess.Enqueue != nil {
		resp["queued"] = a.hostAssess.Enqueue(req.Agent, req.Host)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleFlagAcknowledge marks flags acted-upon (idempotent): one
// {"flag_id"}, or a pattern's {"flag_ids"} (at most model.PatternFlagIDCap)
// in one transaction. Called by the UI when a disposition is applied so the
// flag stops counting as critical — the operator's action and the flag's
// state stay in sync.
func (a *API) handleFlagAcknowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req struct {
		FlagID  string   `json:"flag_id"`
		FlagIDs []string `json:"flag_ids"`
	}
	const invalid = `Invalid payload: {"flag_id"} or {"flag_ids":[...]} (at most 500; ids must match ^[A-Za-z0-9_.-]+$)`
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.FlagID == "") == (len(req.FlagIDs) == 0) {
		http.Error(w, invalid, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if req.FlagID != "" {
		if !guardTokenRE.MatchString(req.FlagID) {
			http.Error(w, invalid, http.StatusBadRequest)
			return
		}
		ok := a.store.AcknowledgeFlag(req.FlagID)
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "acknowledged": ok})
		return
	}
	if len(req.FlagIDs) > model.PatternFlagIDCap {
		http.Error(w, invalid, http.StatusBadRequest)
		return
	}
	for _, id := range req.FlagIDs {
		if !guardTokenRE.MatchString(id) {
			http.Error(w, invalid, http.StatusBadRequest)
			return
		}
	}
	n := a.store.AcknowledgeFlags(req.FlagIDs)
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "acknowledged": n > 0, "count": n})
}

// handleAdvisorRetriage re-queues one flag for a fresh advisor verdict.
// Idempotent by design: repeated requests within the advisor's cooldown are
// no-ops that still answer ok — the client can hammer it without flooding
// the model queue.
func (a *API) handleAdvisorRetriage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.retriage == nil || a.retriage.LookupFlag == nil || a.retriage.Enqueue == nil {
		http.Error(w, "advisor not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		FlagID string `json:"flag_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FlagID == "" {
		http.Error(w, `Invalid payload: {"flag_id"}`, http.StatusBadRequest)
		return
	}
	fl, ok := a.retriage.LookupFlag(req.FlagID)
	if !ok {
		http.Error(w, "flag not found", http.StatusNotFound)
		return
	}
	queued := a.retriage.Enqueue(fl)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "queued": queued})
}

// SetMute wires operator dispositions: (rule, host) pairs the operator said
// "stop telling me about", persisted like the other override stores.

// SetNotifyRules wires the per-rule notification override store so the UIs
// can read and set "page me / never page me for this class" choices.

// SetNotifyScopes wires the per-workspace notification scope store — the more
// specific tier over the per-rule override ("prod repo pages, scratch clones
// stay quiet").

// DefaultNotifyMinSeverity is the default notification policy: warnings are
// queued silently, only criticals page. Per-rule overrides sit on top.
const DefaultNotifyMinSeverity = 3

// handleNotifyRules reads (GET) and writes (POST) notification overrides.
// Two tiers are exposed here:
//
//	per-rule  — POST {"rule":"<id>","notify":true|false|null}
//	per-workspace+rule — POST {"workspace":"/repo","rule":"<id>","notify":…}
//
// A workspace scope is the more specific tier: it beats the per-rule override
// and the default, matched by path prefix (longest first). GET returns both,
// so the console renders the full decision order.
func (a *API) handleNotifyRules(w http.ResponseWriter, r *http.Request) {
	if a.notifyRules == nil {
		http.Error(w, "notify rules not enabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		resp := map[string]any{
			"default_min_severity": DefaultNotifyMinSeverity,
			"overrides":            a.notifyRules.Load(),
			"scopes":               []correlate.NotifyScopePair{},
		}
		if a.notifyScopes != nil {
			resp["scopes"] = a.notifyScopes.Pairs()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		limitBody(w, r)
		var req struct {
			Rule      string `json:"rule"`
			Workspace string `json:"workspace"`
			Notify    *bool  `json:"notify"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !guardTokenRE.MatchString(req.Rule) {
			http.Error(w, `Invalid payload: {"rule":"<id>","notify":true|false|null[,"workspace":"/path"]}`, http.StatusBadRequest)
			return
		}
		// Workspace scope path: the flag's workspace or the rule's per-rule
		// tier. A workspace is required to use the scoped tier.
		if req.Workspace != "" {
			if a.notifyScopes == nil {
				http.Error(w, "workspace notification scopes not enabled", http.StatusServiceUnavailable)
				return
			}
			var err error
			action := "notify-scope-clear"
			detail := "cleared notification scope for " + req.Workspace + " / " + req.Rule
			if req.Notify != nil {
				err = a.notifyScopes.Set(req.Workspace, req.Rule, *req.Notify)
				action = "notify-scope-set"
				detail = map[bool]string{true: "always notify", false: "never notify"}[*req.Notify] + " for " + req.Rule + " in " + req.Workspace
			} else {
				err = a.notifyScopes.Clear(req.Workspace, req.Rule)
			}
			if err != nil {
				http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
				return
			}
			a.store.PutAudit(store.AuditEntry{Action: action, Rule: req.Rule, Detail: detail})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "rule": req.Rule, "workspace": req.Workspace})
			return
		}
		var err error
		action := "notify-rule-clear"
		detail := "cleared notification override for " + req.Rule
		if req.Notify != nil {
			err = a.notifyRules.Set(req.Rule, *req.Notify)
			action = "notify-rule-set"
			detail = map[bool]string{true: "always notify", false: "never notify"}[*req.Notify] + " for " + req.Rule
		} else {
			err = a.notifyRules.Clear(req.Rule)
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		a.store.PutAudit(store.AuditEntry{Action: action, Rule: req.Rule, Detail: detail})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "rule": req.Rule})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// SetUIPID pins the trusted mutating client (the owning menubar app). When
// set, mutating endpoints (kill, guard resolve, firewall promote) require the
// peer to BE that process — same-uid shells keep read access but can no
// longer mutate. When unset (daemon launched directly), mutations fall back
// to owner-uid trust, which is what headless/ssh management uses.

// SetPeers enables unix-socket peer-credential gating. AgentPIDs supplies the
// live tagged-agent pid set used to recognize hook traffic; a nil function or
// nil checker leaves the API ungated (unit tests).

// routes maps every registered path to its handler. The path set is the
// apiroutes.Table (the single source of truth shared with the console
// allow-list and the peer-role gate); this map supplies the handler. A test
// (TestRouteTableMatchesHandlers) asserts the two agree, so a route can no
// longer be added to one list and forgotten in another.
func (a *API) routes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/status":                       a.handleStatus,
		"/sessions":                     a.handleSessions,
		"/sessions/":                    a.handleSessionSubpath,
		"/resources":                    a.handleResources,
		"/resources/episodes":           a.handleResourceEpisodes,
		"/resources/control":            a.handleResourceControl,
		"/resources/policy":             a.handleResourcePolicy,
		"/snapshot":                     a.handleSnapshot,
		"/posture":                      a.handlePosture,
		"/flags":                        a.handleFlags,
		"/flags/":                       a.handleFlagExplain,
		"/events":                       a.handleEvents,
		"/events/stream":                a.handleEventStream,
		"/incidents":                    a.handleIncidents,
		"/incidents/status":             a.handleIncidentStatus,
		"/audit":                        a.handleAudit,
		"/allowlist/suggestions":        a.handleAllowlistSuggestions,
		"/allowlist":                    a.handleAllowlistAdd,
		"/egress/uninspected":           a.handleUninspectedEgress,
		"/egress/endpoint":              a.handleEndpointDetail,
		"/notify/rules":                 a.handleNotifyRules,
		"/guard/path-allow":             a.handleGuardPathAllow,
		"/mute":                         a.handleMute,
		"/advisor/retriage":             a.handleAdvisorRetriage,
		"/advisor/assess-host":          a.handleAdvisorAssessHost,
		"/flags/acknowledge":            a.handleFlagAcknowledge,
		"/patterns":                     a.handlePatterns,
		"/ui/open-fda":                  a.handleOpenFDA,
		"/stats/rollup":                 a.handleRollup,
		"/costs":                        a.handleCosts,
		"/costs/unpriced":               a.handleCostsUnpriced,
		"/costs/plans":                  a.handleCostsPlans,
		"/doctor":                       a.handleDoctor,
		"/worktrees":                    a.handleWorktrees,
		"/worktrees/repos":              a.handleWorktreeRepos,
		"/worktrees/remove":             a.handleWorktreeRemove,
		"/worktrees/advise":             a.handleWorktreeAdvise,
		"/worktrees/reveal":             a.handleWorktreeReveal,
		"/worktrees/reconnect":          a.handleWorktreeReconnect,
		"/worktrees/trash":              a.handleWorktreeTrash,
		"/cleanup/ledger":               a.handleCleanupLedger,
		"/cleanup":                      a.handleCleanup,
		"/worktrees/ask":                a.handleWorktreeAsk,
		"/worktrees/asks":               a.handleWorktreeAsks,
		"/cleanup/trash":                a.handleCleanupTrash,
		"/cleanup/clean":                a.handleCleanupClean,
		"/cleanup/advise":               a.handleCleanupAdvise,
		"/advisor/discover":             a.handleAdvisorDiscover,
		"/fleet":                        a.handleFleet,
		"/kill":                         a.handleKill,
		"/firewall/mode":                a.handleFirewallMode,
		"/firewall/fingerprints/reload": a.handleFingerprintReload,
		"/firewall/fingerprints/ingest": a.handleFingerprintIngest,
		"/firewall/sources":             a.handleFirewallSources,
		"/guard/decision":               a.handleGuardDecision,
		"/guard/pending":                a.handleGuardPending,
		"/guard/resolve":                a.handleGuardResolve,
		"/guard/rules":                  a.handleGuardRules,
		"/debug/pprof/":                 handlePprof,
		"/files/detail":                 a.handleFileDetail,
		"/files/reveal":                 a.handleFileReveal,
		"/files/open":                   a.handleFileOpen,
		"/advisor/plan":                 a.handleAdvisorPlan,
		"/labels":                       a.handleLabels,
		"/agent/status":                 a.handleAgentStatus,
		"/agent/skills":                 a.handleAgentSkills,
		"/agent/chat":                   a.handleAgentChat,
		"/agent/plans":                  a.handleAgentPlans,
		"/agent/dispatch":               a.handleAgentDispatch,
		"/agent/runs":                   a.handleAgentRuns,
	}
}

// buildMux registers every API route on a fresh mux, driven by apiroutes.Table
// so the mux, the peer-role gate and the console allow-list cannot drift.
// Serve() wraps it with the peer-credential gate for the unix socket;
// ConsoleHandler() exposes it ungated for the proxy listener, where
// authentication is the console token (peer creds don't exist on a TCP
// connection).
func (a *API) buildMux() *http.ServeMux { return a.mux(true) }

// mux registers the table's routes; OwnerOnly routes only on the socket mux.
func (a *API) mux(socket bool) *http.ServeMux {
	mux := http.NewServeMux()
	handlers := a.routes()
	for _, r := range apiroutes.Table {
		if r.OwnerOnly && !socket {
			continue
		}
		if h, ok := handlers[r.Path]; ok {
			if r.NoAgent && !socket {
				h = a.consoleNoAgent(h)
			}
			mux.HandleFunc(r.Path, h)
		}
	}
	a.setupWebDashboard(mux)
	return mux
}

// ConsoleHandler returns the API mux WITHOUT the unix-socket peer gate, for
// the proxy listener's console-token-gated routes. /guard/decision is
// deliberately absent from the proxy listener's whitelist (see
// proxy.isConsoleAPIPath) even though it is registered here; OwnerOnly
// routes (/debug/pprof/) are not registered on it at all.
func (a *API) ConsoleHandler() http.Handler { return a.mux(false) }

func (a *API) Serve(ctx context.Context) error {
	if a.socketPath == "" {
		return errors.New("socket path cannot be empty")
	}

	if err := os.MkdirAll(filepath.Dir(a.socketPath), 0o700); err != nil {
		return fmt.Errorf("failed to create socket dir: %w", err)
	}

	_ = os.Remove(a.socketPath) // remove stale socket file if present

	oldMask := unix.Umask(0077)
	listener, err := net.Listen("unix", a.socketPath)
	unix.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket: %w", err)
	}
	// Never unlink the socket file on exit. Go's UnixListener.Close removes
	// the path by default, and when two daemons overlap (old instance exiting
	// while the new one binds), the old one's Close unlinks the NEW daemon's
	// live socket — a healthy daemon left unreachable on an unlinked path.
	// Stale socket files are harmless: startup removes them before binding,
	// and a client of a stale path gets ECONNREFUSED, same as a missing file.
	if ul, ok := listener.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	defer listener.Close()

	_ = os.Chmod(a.socketPath, 0o600)

	server := &http.Server{
		Handler:     a.gate(a.peerChk, a.buildMux()),
		ConnContext: gateConnContext,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.currentStatus())
}

// handleSessions serves the durable session list — live and ended sessions
// with harness, workspace, repo and branch. This is the spine; the process
// tree is just its live projection. ?status=active|idle|ended, ?limit=N,
// ?harness=, ?repo=, ?branch= (exact), ?since=24h|7d|<RFC3339>.
func (a *API) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	f := store.SessionFilter{Status: q.Get("status"), Harness: q.Get("harness"), Repo: q.Get("repo"), Branch: q.Get("branch")}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		f.Limit = n
	}
	if v := q.Get("since"); v != "" {
		t, err := parseSince(v, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.Since = t
	}
	writeJSON(w, a.store.ListSessions(f))
}

// handleSessionSubpath serves the /sessions/{id}/… family: timeline and
// report. Any other shape is 404.
func (a *API) handleSessionSubpath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/sessions/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch parts[1] {
	case "timeline":
		a.serveSessionTimeline(w, r, parts[0])
	case "report":
		a.serveSessionReport(w, r, parts[0])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// serveSessionTimeline serves one session's events oldest-first — the
// timeline the console renders for a selected session. Path shape:
// /sessions/{id}/timeline[?limit=N].
func (a *API) serveSessionTimeline(w http.ResponseWriter, r *http.Request, id string) {
	f := store.EventFilter{SessionID: id, Limit: 500}
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		f.Limit = n
	}
	events := a.store.QueryEvents(f)
	// QueryEvents returns newest-first; a timeline reads oldest-first.
	slices.Reverse(events)
	writeJSON(w, events)
}

func (a *API) currentStatus() Status {
	st := a.statusFn()
	if len(st.Agents) > 0 {
		pids := make([]int32, len(st.Agents))
		for i, ag := range st.Agents {
			pids[i] = ag.PID
		}
		times := a.store.LastEventTimes(pids)
		for i := range st.Agents {
			if ts, ok := times[st.Agents[i].PID]; ok {
				st.Agents[i].LastSeenAt = ts
			}
		}
	}
	st.Trees = GroupAgentTrees(st.Agents)
	// Join each tree root to its durable session (by root pid) so the menubar
	// and console can label a row with the harness + repo@branch the session
	// knows — the process cwd alone reads as "/" for many agents.
	if byRoot := a.store.SessionsByRootPID(); len(byRoot) > 0 {
		for i := range st.Trees {
			root := &st.Trees[i].Root
			pid := root.RootPID
			if pid == 0 {
				pid = root.PID
			}
			if sess, ok := byRoot[pid]; ok {
				if root.SessionID == "" {
					root.SessionID = sess.ID
				}
				if root.Workspace == "" {
					root.Workspace = sess.Workspace
				}
				if root.Repo == "" {
					root.Repo = sess.Repo
				}
				if root.Branch == "" {
					root.Branch = sess.Branch
				}
				if root.Origin == "" {
					root.Origin = sess.Origin
				}
			}
		}
	}
	st.UnactedFlags24h = len(a.store.QueryFlags(store.FlagFilter{
		Unacted:     true,
		MinSeverity: 2,
		Since:       time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		Limit:       500,
	}))
	if a.busDrops != nil {
		st.BusDrops = a.busDrops()
	}
	return st
}

func (a *API) handleFlags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	f := store.FlagFilter{
		Agent: q.Get("agent"),
		Rule:  q.Get("rule"),
		Since: q.Get("since"),
		Limit: min(queryInt(q.Get("limit"), 50), 1000),
	}
	f.MinSeverity = queryInt(q.Get("min_severity"), 0)
	// ?unacted=1 excludes acknowledged flags — reviewed rows must not bury
	// the open ones inside a limit window full of handled noise.
	f.Unacted = q.Get("unacted") == "1" || q.Get("unacted") == "true"
	w.Header().Set("Content-Type", "application/json")
	flags := a.store.QueryFlags(f)
	// Stamp the rule title so clients render the daemon's words instead of
	// keeping their own copies of the rule→title table.
	for i := range flags {
		flags[i].Title = humanFlagTitle(flags[i].Rule)
	}
	a.stampExplains(flags)
	json.NewEncoder(w).Encode(flags)
}

func (a *API) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	f := store.EventFilter{
		Since: q.Get("since"),
		Limit: queryInt(q.Get("limit"), 50),
	}
	if kStr := q.Get("kind"); kStr != "" {
		if k, err := strconv.Atoi(kStr); err == nil {
			f.Kind = &k
		}
	}
	if pid := queryInt(q.Get("pid"), 0); pid > 0 {
		f.PID = int32(pid)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(priceClassed(a.store.QueryEvents(f)))
}

// priceClassed stamps each model_call row with its price class, so the
// console can say "plan" or "unpriced" where cost_usd is 0.
func priceClassed(evs []event.Event) []event.Event {
	for i := range evs {
		evs[i].PriceClass = collect.EventPriceClass(evs[i])
	}
	return evs
}

// queryInt parses a query-param int, returning def when absent or invalid.
func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func (a *API) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id != "" {
		inc, err := a.store.GetIncident(id)
		if err != nil {
			http.Error(w, "Incident not found", http.StatusNotFound)
			return
		}
		format := r.URL.Query().Get("format")
		if format == "markdown" || format == "md" {
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			analyzer := intel.NewAnalyzer()
			w.Write([]byte(analyzer.GenerateMarkdown(*inc)))
			return
		}
		// The report plus its workflow state, so UIs can render one object.
		wf, _ := a.store.IncidentStatus(inc.ID)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, map[string]any{"incident": inc, "workflow": wf})
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	w.Header().Set("Content-Type", "application/json")
	incidents := a.store.RecentIncidents(limit)
	type withStatus struct {
		model.IncidentReport
		Workflow store.IncidentWorkflow `json:"workflow"`
	}
	out := make([]withStatus, 0, len(incidents))
	for i := range incidents {
		wf, _ := a.store.IncidentStatus(incidents[i].ID)
		out = append(out, withStatus{IncidentReport: incidents[i], Workflow: wf})
	}
	writeJSON(w, out)
}

type incidentStatusRequest struct {
	ID     string `json:"id"`
	Status string `json:"status"` // open | acknowledged | resolved
	Note   string `json:"note,omitempty"`
}

// maxAPIBodyBytes bounds every JSON body the control API accepts. The socket
// is same-uid local, but an unbounded decode still lets any local process pin
// daemon memory by streaming garbage at a POST endpoint.
const maxAPIBodyBytes = 1 << 20 // 1 MiB

func limitBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodyBytes)
}

// handleIncidentStatus transitions an incident's workflow state. Audited:
// who-did-we-decide-about-what is exactly what the audit trail is for.
func (a *API) handleIncidentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req incidentStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, `Invalid payload: {"id","status":"open|acknowledged|resolved","note":"..."}`, http.StatusBadRequest)
		return
	}
	ok, err := a.store.SetIncidentStatus(req.ID, req.Status, req.Note)
	if err != nil {
		http.Error(w, fmt.Sprintf("status update failed: %v", err), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "Incident not found", http.StatusNotFound)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "incident-status", Rule: req.ID, ToMode: req.Status, Detail: req.Note})
	wf, _ := a.store.IncidentStatus(req.ID)
	writeJSON(w, map[string]any{"status": "ok", "workflow": wf})
}

func (a *API) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.store.RecentAudit(limit))
}

// handleRollup serves the pre-aggregated hourly counters that power the
// console's activity chart (24h/7d trend views). Read-gated.
func (a *API) handleRollup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if parsed, err := strconv.Atoi(h); err == nil && parsed > 0 {
			hours = parsed
		}
	}
	if hours > 24*31 {
		hours = 24 * 31 // one retention window is the useful ceiling
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.store.RollupRange(time.Now().Add(-time.Duration(hours) * time.Hour)))
}

// handleOpenFDA deep-links the operator to System Settings → Full Disk
// Access — the one-click fix when the eslogger collector is down (the
// posture item names the fix; this makes it one click). Mutation-gated like
// every action that changes machine state.
func (a *API) handleOpenFDA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const fdaURL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
	if err := exec.Command("open", fdaURL).Start(); err != nil {
		http.Error(w, fmt.Sprintf("could not open settings: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// MutePair is one operator disposition: (rule, host) suppressed at the
// correlator (counted, never flagged) for Agent, or for every agent when
// Agent is empty. Title is the rule's human title, served on reads only;
// POST ignores it.
type MutePair struct {
	Rule  string `json:"rule"`
	Host  string `json:"host"`
	Agent string `json:"agent,omitempty"`
	Title string `json:"title,omitempty"`
}

// handleMute lists dispositions (GET, read-gated), records one (POST,
// mutation-gated), or removes one (DELETE, owner-level).
func (a *API) handleMute(w http.ResponseWriter, r *http.Request) {
	if a.mutes == nil {
		http.Error(w, "mute store not enabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.mutePairs())
	case http.MethodPost:
		limitBody(w, r)
		var req MutePair
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Rule == "" || req.Host == "" {
			http.Error(w, `Invalid payload: {"rule":"<id>","host":"<host>","agent":"<optional agent>"}`, http.StatusBadRequest)
			return
		}
		if !validMuteHost(req.Host) {
			http.Error(w, "host must be a bare hostname", http.StatusBadRequest)
			return
		}
		if !validMuteAgent(req.Agent) {
			http.Error(w, "invalid agent", http.StatusBadRequest)
			return
		}
		if err := a.mutes.Add(req.Rule, req.Host, req.Agent); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		// Close the loop on existing rows: every unacknowledged flag of this
		// rule citing this host leaves the critical list. Without this, a
		// mute suppresses only FUTURE flags and the operator sees "nothing
		// happened" — the old rows sit there, red, forever.
		acked := a.store.AcknowledgeRuleHost(req.Rule, req.Host, req.Agent)
		a.recordLabel(model.OperatorLabel{Kind: "host", Rule: req.Rule, Agent: req.Agent, Pattern: req.Host, Label: "ok", Source: "mute"})
		a.store.PutAudit(store.AuditEntry{
			Action: "mute-add", Rule: req.Rule,
			Detail: fmt.Sprintf("muted %s for %s%s (%d existing flags acknowledged)", req.Host, req.Rule, muteAgentSuffix(req.Agent), acked),
		})
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{"status": "ok", "rule": req.Rule, "host": req.Host}
		if req.Agent != "" {
			resp["agent"] = req.Agent
		}
		json.NewEncoder(w).Encode(resp)
	case http.MethodDelete:
		rule, host, agent := r.URL.Query().Get("rule"), r.URL.Query().Get("host"), r.URL.Query().Get("agent")
		if rule == "" || host == "" {
			http.Error(w, "DELETE requires ?rule=<id>&host=<host>[&agent=<agent>]", http.StatusBadRequest)
			return
		}
		// Same host validation as POST: a bare hostname only (a mute value
		// with URL structure or absurd length could poison the store and
		// the ledger UI). Rule must match the id charset.
		if !guardTokenRE.MatchString(rule) || !validMuteHost(host) || !validMuteAgent(agent) {
			http.Error(w, "invalid rule/host/agent", http.StatusBadRequest)
			return
		}
		if err := a.mutes.Remove(rule, host, agent); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		a.store.PutAudit(store.AuditEntry{
			Action: "mute-remove", Rule: rule,
			Detail: fmt.Sprintf("unmuted %s for %s%s", host, rule, muteAgentSuffix(agent)),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdvisorDiscover lists loopback OpenAI-compatible model servers the
// user could link (Path B: existing Ollama/MLX/llama.cpp servers) plus the
// curated managed-model list (Path A), this machine's profile and the models
// ranked for it. Read-gated; the menubar's Advisor settings pane and
// onboarding render from this so nobody types an endpoint.
func (a *API) handleAdvisorDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	servers := advisor.DiscoverServers()
	machine := advisor.MachineProfile()
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]any{
		"servers":         servers,
		"managed_models":  advisor.DefaultManagedModels,
		"machine":         machine,
		"recommendations": advisor.Recommend(machine, servers),
	})
}

// Suggestion is one allowlist candidate: an agent+host pair seen bypassing
// inspection often enough to be worth a decision (threshold keeps one-off
// noise from nagging). Assessment carries the advisor's pre-computed host
// legitimacy verdict when one exists.
type Suggestion struct {
	Agent      string                     `json:"agent"`
	Host       string                     `json:"host"`
	Count      int                        `json:"count"`
	Identity   correlate.EndpointIdentity `json:"identity"`
	Assessment string                     `json:"assessment,omitempty"`
	Rationale  string                     `json:"rationale,omitempty"`
	Confidence float64                    `json:"confidence,omitempty"`
}

// minSuggestionCount: a host must recur before we suggest anything — a single
// stray connection is noise, a pattern is policy input.
const minSuggestionCount = 3

// handleAllowlistSuggestions lists recurring uninspected egress endpoints,
// most frequent first, with the advisor's host assessment when available.
// Read-level.
func (a *API) handleAllowlistSuggestions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.suggestionList())
}

// UninspectedEndpoint is one blind-spot row for the drill-down behind the
// posture warning: which agent reached which host without inspection, how
// often, and when last — with the advisor's verdict when one exists.
type UninspectedEndpoint struct {
	Agent      string                     `json:"agent"`
	Host       string                     `json:"host"`
	Count      int                        `json:"count"`
	FirstSeen  *time.Time                 `json:"first_seen,omitempty"`
	LastSeen   time.Time                  `json:"last_seen"`
	SessionID  string                     `json:"session_id,omitempty"`
	Infra      string                     `json:"infra,omitempty"`
	Identity   correlate.EndpointIdentity `json:"identity"`
	Assessment string                     `json:"assessment,omitempty"`
	Rationale  string                     `json:"rationale,omitempty"`
}

// uninspectedRows builds the blind-spot rows last seen at or after since,
// most frequent first, with the advisor's host verdict joined, capped at limit.
func (a *API) uninspectedRows(since time.Time, limit int) []UninspectedEndpoint {
	out := []UninspectedEndpoint{}
	if a.correlator == nil {
		return out
	}
	for _, e := range a.correlator.UninspectedEgressSummarySince(since) {
		ep := UninspectedEndpoint{Agent: e.Agent, Host: e.Host, Count: e.Count, LastSeen: e.LastSeen,
			SessionID: e.SessionID, Infra: e.Infra, Identity: e.Identity}
		if !e.FirstSeen.IsZero() {
			t := e.FirstSeen
			ep.FirstSeen = &t
		}
		if v, ok := a.store.AdvisorVerdictFor("host:"+e.Agent+"|"+e.Host, "host"); ok {
			ep.Assessment = v.Assessment
			ep.Rationale = v.Rationale
		}
		out = append(out, ep)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// handleUninspectedEgress lists the endpoints behind the "N connections
// bypassed the egress firewall" warning so the number is explainable and
// actionable instead of a dead end. Read-level. ?hours= (1..168, default 24)
// windows the list; ?limit= caps rows (default 200).
func (a *API) handleUninspectedEgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hours := queryInt(r.URL.Query().Get("hours"), 24)
	if hours < 1 || hours > 168 {
		hours = 24
	}
	limit := queryInt(r.URL.Query().Get("limit"), 200)
	out := a.uninspectedRows(time.Now().Add(-time.Duration(hours)*time.Hour), limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// EndpointDetail answers "what is this endpoint?" for one host: its identity
// (org, resolved name, v4/v6), every agent that reached it, the sessions
// involved, and the recent connection events. The Evidence action on an egress
// row opens this so an unknown IPv6 is explainable instead of a bare address
// that invites blocking rightful traffic.
type EndpointDetail struct {
	Host      string                     `json:"host"`
	Identity  correlate.EndpointIdentity `json:"identity"`
	Agents    []string                   `json:"agents"`
	Sessions  []model.Session            `json:"sessions"`
	Count     int                        `json:"count"`
	FirstSeen *time.Time                 `json:"first_seen,omitempty"`
	LastSeen  *time.Time                 `json:"last_seen,omitempty"`
	Infra     string                     `json:"infra,omitempty"`
	// Allowed is set when the operator has already approved this host for any
	// agent — so the drawer shows "already allowed" instead of offering it.
	Allowed []EndpointAllowance `json:"allowed,omitempty"`
	Events  []event.Event       `json:"events"`
}

// EndpointAllowance is one existing allowlist entry for the endpoint.
type EndpointAllowance struct {
	Agent string `json:"agent"`
	Host  string `json:"host"`
}

func (a *API) handleEndpointDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	if host == "" {
		http.Error(w, `missing ?host=`, http.StatusBadRequest)
		return
	}
	detail := EndpointDetail{
		Host:     host,
		Identity: correlate.Identify(host),
		Agents:   []string{},
		Sessions: []model.Session{},
		Allowed:  []EndpointAllowance{},
		Events:   []event.Event{},
	}
	// Aggregate every agent+host summary matching this host (case-insensitive;
	// the summaries key on the lowercased host).
	if a.correlator != nil {
		for _, e := range a.correlator.UninspectedEgressSummarySince(time.Time{}) {
			if !strings.EqualFold(e.Host, host) {
				continue
			}
			detail.Agents = append(detail.Agents, e.Agent)
			detail.Count += e.Count
			if !e.FirstSeen.IsZero() && (detail.FirstSeen == nil || e.FirstSeen.Before(*detail.FirstSeen)) {
				t := e.FirstSeen
				detail.FirstSeen = &t
			}
			if !e.LastSeen.IsZero() && (detail.LastSeen == nil || e.LastSeen.After(*detail.LastSeen)) {
				t := e.LastSeen
				detail.LastSeen = &t
			}
			if detail.Infra == "" {
				detail.Infra = e.Infra
			}
		}
	}
	sort.Strings(detail.Agents)
	detail.Agents = slices.Compact(detail.Agents)

	// Recent connection events to this host, and the durable sessions behind
	// them (so "claude reached it" comes with the repo/branch it was working in).
	evs := a.store.QueryEvents(store.EventFilter{
		RemoteHost: host,
		Since:      time.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Limit:      50,
	})
	detail.Events = evs
	seen := map[string]bool{}
	for _, e := range evs {
		if e.SessionID == "" || seen[e.SessionID] {
			continue
		}
		seen[e.SessionID] = true
		if s, ok := a.store.GetSession(e.SessionID); ok {
			detail.Sessions = append(detail.Sessions, s)
		}
	}

	// Existing allowances for this host (any agent) — so the drawer can say
	// "already trusted for X" instead of re-offering Allow.
	if a.allowlist != nil {
		for agent, hosts := range a.allowlist.Load() {
			for _, h := range hosts {
				if correlate.HostMatches(host, h) {
					detail.Allowed = append(detail.Allowed, EndpointAllowance{Agent: agent, Host: h})
				}
			}
		}
		sort.Slice(detail.Allowed, func(i, j int) bool { return detail.Allowed[i].Agent < detail.Allowed[j].Agent })
	}

	writeJSON(w, detail)
}

// handleAllowlistAdd approves one host for one agent: persists the override,
// makes the correlator treat the host as vendor traffic, drops it from the
// blind-spot set, and audits the decision. Mutation-gated.
func (a *API) handleAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	if a.allowlist == nil || a.correlator == nil {
		http.Error(w, "allowlist not enabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		// Current user-approved (agent, host) overrides, sorted — the console
		// renders them with working Remove buttons (approvals are reversible).
		type pair struct {
			Agent string `json:"agent"`
			Host  string `json:"host"`
		}
		out := []pair{}
		for agent, hosts := range a.allowlist.Load() {
			for _, h := range hosts {
				out = append(out, pair{Agent: agent, Host: h})
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Agent != out[j].Agent {
				return out[i].Agent < out[j].Agent
			}
			return out[i].Host < out[j].Host
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	case http.MethodDelete:
		limitBody(w, r)
		var req struct {
			Agent string `json:"agent"`
			Host  string `json:"host"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.Host == "" {
			http.Error(w, `Invalid payload: {"agent":"<name>","host":"<host>"}`, http.StatusBadRequest)
			return
		}
		if err := a.allowlist.Remove(req.Agent, req.Host); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		a.store.PutAudit(store.AuditEntry{
			Action: "allowlist-remove", Rule: req.Agent,
			Detail: fmt.Sprintf("removed %s for %s", req.Host, req.Agent),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req struct {
		Agent string `json:"agent"`
		Host  string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.Host == "" {
		http.Error(w, `Invalid payload: {"agent":"<name>","host":"<host>"}`, http.StatusBadRequest)
		return
	}
	// A suggestion is a hostname or an IP literal, never a URL, a path, or a
	// host:port pair — reject anything with structure so the allowlist can't be
	// widened by smuggling. Bare IPv6 literals contain ':' and must be
	// admitted: agents reach IPv6-only endpoints, and the suggestions list now
	// surfaces them (they were previously un-approvable with a 400).
	if !validAllowlistHost(req.Host) {
		http.Error(w, "host must be a bare hostname or IP address", http.StatusBadRequest)
		return
	}
	if err := a.allowlist.Add(req.Agent, req.Host); err != nil {
		http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
		return
	}
	a.correlator.NoteAllowlistAdded(req.Agent, req.Host)
	a.recordLabel(model.OperatorLabel{Kind: "host", Agent: req.Agent, Pattern: req.Host, Label: "ok", Source: "allow-host"})
	a.store.PutAudit(store.AuditEntry{
		Action: "allowlist-add", Rule: req.Agent,
		Detail: fmt.Sprintf("approved %s for %s", req.Host, req.Agent),
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "agent": req.Agent, "host": req.Host})
}

// validAllowlistHost admits a bare DNS name or an IP literal (IPv4 or IPv6).
// It rejects anything carrying URL/path/port structure so the allowlist cannot
// be widened by smuggling — while still admitting the IPv6 literals agents
// actually reach (previously any ':' was rejected, so IPv6-only endpoints
// could never be approved).
func validAllowlistHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	// URL/path structure is never a host.
	if strings.ContainsAny(host, "/@?#") || strings.Contains(host, "://") {
		return false
	}
	// A bare IPv6 literal: valid per net.ParseIP, must not be bracketed or
	// carry a zone (the net sample stores the bare address).
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	// Reject bracketed IPv6 ([::1]) and any embedded colon: for a DNS name a
	// colon means host:port, which is not a bare host.
	if strings.ContainsAny(host, "[]:") {
		return false
	}
	// DNS name: labels of [A-Za-z0-9-], not starting/ending with '-'.
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !ok {
				return false
			}
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
