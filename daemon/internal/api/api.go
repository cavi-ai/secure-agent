package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
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
	"golang.org/x/sys/unix"
)

type Killer interface {
	Kill(pid int32) error
}

type AgentSummary struct {
	PID       int32  `json:"pid"`
	Name      string `json:"name"`
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
}

type Status struct {
	Running           bool           `json:"running"`
	Version           string         `json:"version"`
	Uptime            string         `json:"uptime"`
	ActiveAgents      int            `json:"active_agents"`
	Agents            []AgentSummary `json:"agents"`
	Trees             []AgentTree    `json:"trees"`
	ProxyEnabled      bool           `json:"proxy_enabled"`
	ProxyPort         int            `json:"proxy_port"`
	UninspectedEgress int            `json:"uninspected_egress"`
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
	// hot-path signal the audit asked to surface.
	BusDrops uint64 `json:"bus_drops,omitempty"`

	FirewallStats map[string]firewall.RuleStat `json:"firewall_stats,omitempty"`
	// Collectors reports each supervised worker's health so a dead or abandoned
	// collector cannot appear healthy just because the daemon process is up.
	Collectors []supervise.Health `json:"collectors,omitempty"`
}

type StatusFunc func() Status

type API struct {
	socketPath       string
	store            *store.Store
	killer           Killer
	statusFn         StatusFunc
	resources        func() resource.Snapshot
	resourceControl  *resource.Controller
	resourcePolicy   func(config.ResourceControlConfig) error
	resourcePolicyMu sync.Mutex

	fwEngine      *firewall.Engine
	fwModes       *firewall.ModeStore
	fwReload      func() error
	fwIngest      func() ([]string, error)
	fwSources     *firewall.SourceStore
	fwBaseSources []string

	guardBroker *guard.Broker

	correlator  *correlate.Correlator
	allowlist   *correlate.AllowlistStore
	mutes       *correlate.MuteStore
	notifyRules *correlate.NotifyRuleStore
	retriage    *RetriageFuncs
	guardSeq    uint64

	peerRole   *peers
	peerChk    PeerChecker
	agentPIDs  func() map[int32]struct{}
	fleetSinks GuardEventSink
	// fleetConfigured mirrors len(cfg.Fleet.Webhooks) > 0 so /fleet can tell
	// the console whether a collector exists at all.
	fleetConfigured bool

	subscribeEvents   func() <-chan event.Event
	unsubscribeEvents func(<-chan event.Event)
	publishEvent      func(event.Event)
	busDrops          func() uint64
}

// GuardEventSink receives guard decisions (allow/deny) for downstream
// delivery. Modeled on fleet.Publisher to avoid an import cycle.
type GuardEventSink interface {
	PublishGuardDecision(decision map[string]any)
}

// SetFleetSink wires the fleet publisher for guard-decision delivery.
func (a *API) SetFleetSink(s GuardEventSink) {
	a.fleetSinks = s
}

func (a *API) SetBusDrops(fn func() uint64) { a.busDrops = fn }

func (a *API) SetResources(fn func() resource.Snapshot)        { a.resources = fn }
func (a *API) SetResourceControl(control *resource.Controller) { a.resourceControl = control }
func (a *API) SetResourcePolicyUpdater(fn func(config.ResourceControlConfig) error) {
	a.resourcePolicy = fn
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

func New(socketPath string, store *store.Store, killer Killer, statusFn StatusFunc) *API {
	return &API{
		socketPath: socketPath,
		store:      store,
		killer:     killer,
		statusFn:   statusFn,
	}
}

// SetFirewall wires the firewall engine and its persisted mode-override store so
// the control API can promote/demote rules at runtime. Optional: when unset, the
// /firewall/mode endpoint reports the firewall is not enabled.
func (a *API) SetFirewall(c FirewallControl) {
	a.fwEngine = c.Engine
	a.fwModes = c.Modes
	a.fwReload = c.Reload
	a.fwIngest = c.Ingest
	a.fwSources = c.Sources
	a.fwBaseSources = c.BaseSources
}

// SetGuard wires the directory-guard broker so the control API can answer
// prompt-mode decisions and expose the pending queue / resolve / rules
// endpoints. Optional: when unset, the /guard/* endpoints report the guard is
// not enabled.
func (a *API) SetGuard(b *guard.Broker) {
	a.guardBroker = b
}

// SetAllowlist wires the correlator (blind-spot summary) and the persisted
// user-approval store so the console can suggest allowlist additions and
// approve them with one click.
func (a *API) SetAllowlist(cr *correlate.Correlator, al *correlate.AllowlistStore) {
	a.correlator = cr
	a.allowlist = al
}

// retriageFuncs look up a flag by ID and enqueue it for a fresh advisor
// verdict. The enqueue is idempotent (advisor-side cooldown); queued=false
// means "already in flight or recent" — the UI treats that as success.
type RetriageFuncs struct {
	LookupFlag func(flagID string) (model.Flag, bool)
	Enqueue    func(model.Flag) bool
}

func (a *API) SetRetriage(r RetriageFuncs) { a.retriage = &r }

// handleFlagAcknowledge marks one flag acted-upon (idempotent). Called by
// the UI when a disposition is applied so the flag stops counting as
// critical — the operator's action and the flag's state stay in sync.
func (a *API) handleFlagAcknowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req struct {
		FlagID string `json:"flag_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FlagID == "" ||
		!guardTokenRE.MatchString(req.FlagID) {
		http.Error(w, `Invalid payload: {"flag_id"} (id must match ^[A-Za-z0-9_.-]+$)`, http.StatusBadRequest)
		return
	}
	ok := a.store.AcknowledgeFlag(req.FlagID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "acknowledged": ok})
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
func (a *API) SetMute(cr *correlate.Correlator, ms *correlate.MuteStore) {
	a.correlator = cr
	a.mutes = ms
}

// SetNotifyRules wires the per-rule notification override store so the UIs
// can read and set "page me / never page me for this class" choices.
func (a *API) SetNotifyRules(ns *correlate.NotifyRuleStore) {
	a.notifyRules = ns
}

// DefaultNotifyMinSeverity is the default notification policy: warnings are
// queued silently, only criticals page. Per-rule overrides sit on top.
const DefaultNotifyMinSeverity = 3

// handleNotifyRules reads (GET) and writes (POST) per-rule notification
// overrides. POST body: {"rule":"<id>","notify":true|false|null} — null (or
// absent) clears the override and returns the rule to the default policy.
func (a *API) handleNotifyRules(w http.ResponseWriter, r *http.Request) {
	if a.notifyRules == nil {
		http.Error(w, "notify rules not enabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"default_min_severity": DefaultNotifyMinSeverity,
			"overrides":            a.notifyRules.Load(),
		})
	case http.MethodPost:
		limitBody(w, r)
		var req struct {
			Rule   string `json:"rule"`
			Notify *bool  `json:"notify"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !guardTokenRE.MatchString(req.Rule) {
			http.Error(w, `Invalid payload: {"rule":"<id>","notify":true|false|null}`, http.StatusBadRequest)
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
func (a *API) SetUIPID(pid int32) {
	if a.peerRole != nil {
		a.peerRole.UIPID = pid
	}
}

// SetPeers enables unix-socket peer-credential gating. AgentPIDs supplies the
// live tagged-agent pid set used to recognize hook traffic; a nil function or
// nil checker leaves the API ungated (unit tests).
func (a *API) SetPeers(checker PeerChecker, agentPIDs func() map[int32]struct{}) {
	a.peerChk = checker
	a.agentPIDs = agentPIDs
	if checker == nil {
		return
	}
	a.peerRole = &peers{OwnerUID: os.Getuid(), AgentPIDs: agentPIDs}
}

// buildMux registers every API route on a fresh mux. Serve() wraps it with
// the peer-credential gate for the unix socket; ConsoleHandler() exposes it
// ungated for the proxy listener, where authentication is the console token
// (peer creds don't exist on a TCP connection).
func (a *API) buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", a.handleStatus)
	mux.HandleFunc("/resources", a.handleResources)
	mux.HandleFunc("/resources/control", a.handleResourceControl)
	mux.HandleFunc("/resources/policy", a.handleResourcePolicy)
	mux.HandleFunc("/snapshot", a.handleSnapshot)
	mux.HandleFunc("/posture", a.handlePosture)
	mux.HandleFunc("/flags", a.handleFlags)
	mux.HandleFunc("/events", a.handleEvents)
	mux.HandleFunc("/events/stream", a.handleEventStream)
	mux.HandleFunc("/incidents", a.handleIncidents)
	mux.HandleFunc("/incidents/status", a.handleIncidentStatus)
	mux.HandleFunc("/audit", a.handleAudit)
	mux.HandleFunc("/allowlist/suggestions", a.handleAllowlistSuggestions)
	mux.HandleFunc("/allowlist", a.handleAllowlistAdd)
	mux.HandleFunc("/egress/uninspected", a.handleUninspectedEgress)
	mux.HandleFunc("/notify/rules", a.handleNotifyRules)
	mux.HandleFunc("/guard/path-allow", a.handleGuardPathAllow)
	mux.HandleFunc("/mute", a.handleMute)
	mux.HandleFunc("/advisor/retriage", a.handleAdvisorRetriage)
	mux.HandleFunc("/flags/acknowledge", a.handleFlagAcknowledge)
	mux.HandleFunc("/ui/open-fda", a.handleOpenFDA)
	mux.HandleFunc("/stats/rollup", a.handleRollup)
	mux.HandleFunc("/advisor/discover", a.handleAdvisorDiscover)
	mux.HandleFunc("/fleet", a.handleFleet)
	mux.HandleFunc("/kill", a.handleKill)
	mux.HandleFunc("/firewall/mode", a.handleFirewallMode)
	mux.HandleFunc("/firewall/fingerprints/reload", a.handleFingerprintReload)
	mux.HandleFunc("/firewall/fingerprints/ingest", a.handleFingerprintIngest)
	mux.HandleFunc("/firewall/sources", a.handleFirewallSources)
	mux.HandleFunc("/guard/decision", a.handleGuardDecision)
	mux.HandleFunc("/guard/pending", a.handleGuardPending)
	mux.HandleFunc("/guard/resolve", a.handleGuardResolve)
	mux.HandleFunc("/guard/rules", a.handleGuardRules)
	a.setupWebDashboard(mux)
	return mux
}

// ConsoleHandler returns the API mux WITHOUT the unix-socket peer gate, for
// the proxy listener's console-token-gated routes. /guard/decision is
// deliberately absent from the proxy listener's whitelist (see
// proxy.isConsoleAPIPath) even though it is registered here.
func (a *API) ConsoleHandler() http.Handler { return a.buildMux() }

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
	defer func() {
		listener.Close()
		_ = os.Remove(a.socketPath)
	}()

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

func (a *API) handleResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.resources == nil {
		http.Error(w, "resource telemetry not enabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, a.resources())
}

func (a *API) handleResourceControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.resourceControl == nil {
		http.Error(w, "resource control not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if err := a.resourceControl.Resolve(req.ID, req.Decision, time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "resource-control", Rule: req.ID, ToMode: req.Decision})
	writeJSON(w, map[string]string{"status": "ok", "id": req.ID, "decision": req.Decision})
}

func (a *API) handleResourcePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.resourcePolicy == nil {
		http.Error(w, "resource policy editing not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	reject := func(detail string) {
		a.store.PutAudit(store.AuditEntry{Action: "resource-policy-update-rejected", Detail: detail})
	}
	var next config.ResourceControlConfig
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&next); err != nil {
		reject("invalid payload")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		reject("trailing payload")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if err := config.ValidateResourceControl(next); err != nil {
		reject("validation failed: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.resourcePolicyMu.Lock()
	defer a.resourcePolicyMu.Unlock()
	if err := a.resourcePolicy(next); err != nil {
		a.store.PutAudit(store.AuditEntry{Action: "resource-policy-update-failed", ToMode: next.Mode,
			Detail: fmt.Sprintf("workspace_overrides=%d error=%v", len(next.WorkspaceOverrides), err)})
		http.Error(w, "resource policy was not saved", http.StatusInternalServerError)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "resource-policy-update", ToMode: next.Mode,
		Detail: fmt.Sprintf("workspace_overrides=%d", len(next.WorkspaceOverrides))})
	writeJSON(w, map[string]string{"status": "ok"})
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
		Limit: queryInt(q.Get("limit"), 50),
	}
	f.MinSeverity = queryInt(q.Get("min_severity"), 0)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.store.QueryFlags(f))
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
	json.NewEncoder(w).Encode(a.store.QueryEvents(f))
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

// systemDirs are locations a user secret file never legitimately lives; a source
// under any of them would only turn the root daemon into a system-file reader.
var systemDirs = []string{
	"/etc", "/private/etc", "/System", "/Library",
	"/usr", "/bin", "/sbin", "/var/db", "/private/var/db",
}

// validateSourcePath confines a registered ingest source to a plausible user
// secret file: an absolute regular file, its real path (symlinks resolved) not
// inside a system store. The daemon reads the source as root, so this is the
// gate that keeps source-add from becoming an arbitrary-file-read.
func validateSourcePath(raw string) error {
	p := config.ExpandPath(strings.TrimSpace(raw))
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path must be absolute or ~-relative")
	}
	resolved := filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		resolved = filepath.Clean(r)
	}
	for _, deny := range systemDirs {
		if resolved == deny || strings.HasPrefix(resolved, deny+"/") {
			return fmt.Errorf("refusing to ingest a system path: %s", resolved)
		}
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("not readable: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("must be a regular file")
	}
	return nil
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
// correlator (counted, never flagged).
type MutePair struct {
	Rule string `json:"rule"`
	Host string `json:"host"`
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
			http.Error(w, `Invalid payload: {"rule":"<id>","host":"<host>"}`, http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(req.Host, "/:@") || len(req.Host) > 253 {
			http.Error(w, "host must be a bare hostname", http.StatusBadRequest)
			return
		}
		if err := a.mutes.Add(req.Rule, req.Host); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		// Close the loop on existing rows: every unacknowledged flag of this
		// rule citing this host leaves the critical list. Without this, a
		// mute suppresses only FUTURE flags and the operator sees "nothing
		// happened" — the old rows sit there, red, forever.
		acked := a.store.AcknowledgeRuleHost(req.Rule, req.Host)
		a.store.PutAudit(store.AuditEntry{
			Action: "mute-add", Rule: req.Rule,
			Detail: fmt.Sprintf("muted %s for %s (%d existing flags acknowledged)", req.Host, req.Rule, acked),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "rule": req.Rule, "host": req.Host})
	case http.MethodDelete:
		rule, host := r.URL.Query().Get("rule"), r.URL.Query().Get("host")
		if rule == "" || host == "" {
			http.Error(w, "DELETE requires ?rule=<id>&host=<host>", http.StatusBadRequest)
			return
		}
		// Same host validation as POST: a bare hostname only (a mute value
		// with URL structure or absurd length could poison the store and
		// the ledger UI). Rule must match the id charset.
		if !guardTokenRE.MatchString(rule) || strings.ContainsAny(host, "/:@") || len(host) > 253 {
			http.Error(w, "invalid rule/host", http.StatusBadRequest)
			return
		}
		if err := a.mutes.Remove(rule, host); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		a.store.PutAudit(store.AuditEntry{
			Action: "mute-remove", Rule: rule,
			Detail: fmt.Sprintf("unmuted %s for %s", host, rule),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdvisorDiscover lists loopback OpenAI-compatible model servers the
// user could link (Path B: existing Ollama/MLX/llama.cpp servers) plus the
// curated managed-model list (Path A). Read-gated; the menubar's Advisor
// settings pane renders its dropdowns from this so nobody types an endpoint.
func (a *API) handleAdvisorDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]any{
		"servers":        advisor.DiscoverServers(),
		"managed_models": advisor.DefaultManagedModels,
	})
}

// Suggestion is one allowlist candidate: an agent+host pair seen bypassing
// inspection often enough to be worth a decision (threshold keeps one-off
// noise from nagging). Assessment carries the advisor's pre-computed host
// legitimacy verdict when one exists.
type Suggestion struct {
	Agent      string  `json:"agent"`
	Host       string  `json:"host"`
	Count      int     `json:"count"`
	Assessment string  `json:"assessment,omitempty"`
	Rationale  string  `json:"rationale,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
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
	Agent      string    `json:"agent"`
	Host       string    `json:"host"`
	Count      int       `json:"count"`
	LastSeen   time.Time `json:"last_seen"`
	Assessment string    `json:"assessment,omitempty"`
	Rationale  string    `json:"rationale,omitempty"`
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
	out := []UninspectedEndpoint{}
	if a.correlator != nil {
		for _, e := range a.correlator.UninspectedEgressSummarySince(time.Now().Add(-time.Duration(hours) * time.Hour)) {
			ep := UninspectedEndpoint{Agent: e.Agent, Host: e.Host, Count: e.Count, LastSeen: e.LastSeen}
			if v, ok := a.store.AdvisorVerdictFor("host:"+e.Agent+"|"+e.Host, "host"); ok {
				ep.Assessment = v.Assessment
				ep.Rationale = v.Rationale
			}
			out = append(out, ep)
			if len(out) >= limit {
				break
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// handleAllowlistAdd approves one host for one agent: persists the override,
// makes the correlator treat the host as vendor traffic, drops it from the
// blind-spot set, and audits the decision. Mutation-gated.
func (a *API) handleAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.allowlist == nil || a.correlator == nil {
		http.Error(w, "allowlist not enabled", http.StatusServiceUnavailable)
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
	// A suggestion is a hostname, never a URL or a path — reject anything
	// with structure so the allowlist can't be widened by smuggling.
	if strings.ContainsAny(req.Host, "/:@") || len(req.Host) > 253 {
		http.Error(w, "host must be a bare hostname", http.StatusBadRequest)
		return
	}
	if err := a.allowlist.Add(req.Agent, req.Host); err != nil {
		http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
		return
	}
	a.correlator.NoteAllowlistAdded(req.Agent, req.Host)
	a.store.PutAudit(store.AuditEntry{
		Action: "allowlist-add", Rule: req.Agent,
		Detail: fmt.Sprintf("approved %s for %s", req.Host, req.Agent),
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "agent": req.Agent, "host": req.Host})
}

type killRequest struct {
	PID       int32  `json:"pid"`
	StartedAt string `json:"started_at,omitempty"`
}

// agentPIDs supplies the live tagged-agent pid set for /kill allowlisting;
// nil disables the restriction (unit tests, non-darwin builds).
func (a *API) SetAgentPIDs(fn func() map[int32]struct{}) {
	a.agentPIDs = fn
}

func (a *API) handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req killRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PID <= 0 {
		http.Error(w, "Invalid pid", http.StatusBadRequest)
		return
	}

	killed, err := a.TerminateAgentTree(req.PID, req.StartedAt)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not a recognized") {
			status = http.StatusForbidden
		}
		if strings.Contains(err.Error(), "no longer") || strings.Contains(err.Error(), "start") {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "pid": req.PID, "killed": killed})
}

// TerminateAgentTree is the single guarded containment path used by both the
// operator /kill endpoint and resource budgets.
func (a *API) TerminateAgentTree(pid int32, startedAt string) ([]int32, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid")
	}
	// A control socket that can kill any pid is a self-neutralization
	// primitive (kill the daemon, kill an unrelated user process). Only
	// processes the tagger currently recognizes as agents are valid targets.
	// Re-checked immediately before the kill: between the first check and the
	// signal, the agent can exit and the pid can be recycled by an unrelated
	// process. started_at from the client is compared to the live tagged
	// process so a recycled pid with a different start time is refused.
	if a.agentPIDs != nil {
		if _, ok := a.agentPIDs()[pid]; !ok {
			return nil, fmt.Errorf("pid is not a recognized agent process tree")
		}
		// Re-verify right before signaling to shrink the pid-reuse window.
		if _, ok := a.agentPIDs()[pid]; !ok {
			return nil, fmt.Errorf("pid is no longer a recognized agent process")
		}
	}

	if startedAt != "" {
		if err := a.checkKillStart(pid, startedAt); err != nil {
			return nil, err
		}
	}

	// UI copy, CLI, and flag actions all say "process tree". Kill every
	// currently tagged agent that shares this pid's root_pid — not the OS
	// process tree, only what the tagger already recognized.
	var killed []int32
	for _, memberPID := range a.killTreePIDs(pid) {
		if a.agentPIDs != nil {
			if _, ok := a.agentPIDs()[memberPID]; !ok {
				continue
			}
		}
		if err := a.killer.Kill(memberPID); err != nil {
			return killed, fmt.Errorf("Kill failed: %w", err)
		}
		killed = append(killed, memberPID)
	}
	return killed, nil
}

func (a *API) killTreePIDs(pid int32) []int32 {
	st := a.statusFn()
	root := pid
	found := false
	for _, ag := range st.Agents {
		if ag.PID != pid {
			continue
		}
		found = true
		if ag.RootPID != 0 {
			root = ag.RootPID
		}
		break
	}
	if !found {
		return []int32{pid}
	}
	var helpers, roots []int32
	seen := map[int32]struct{}{}
	for _, ag := range st.Agents {
		r := ag.RootPID
		if r == 0 {
			r = ag.PID
		}
		if r != root {
			continue
		}
		if _, ok := seen[ag.PID]; ok {
			continue
		}
		seen[ag.PID] = struct{}{}
		if ag.PID == root {
			roots = append(roots, ag.PID)
		} else {
			helpers = append(helpers, ag.PID)
		}
	}
	if len(roots) == 0 {
		roots = []int32{root}
	}
	return append(helpers, roots...)
}

func (a *API) checkKillStart(pid int32, startedAt string) error {
	st := a.statusFn()
	for _, ag := range st.Agents {
		if ag.PID != pid {
			continue
		}
		if ag.StartedAt != "" && ag.StartedAt != startedAt {
			return fmt.Errorf("pid %d start time mismatch (process recycled?)", pid)
		}
		return nil
	}
	return nil
}

type fwModeRequest struct {
	Rule string `json:"rule"`
	Type string `json:"type"` // when rule is empty: promote every pattern of this secret type
	Mode string `json:"mode"` // "monitor" | "block"
}

func (a *API) applyRuleMode(rule, mode string) error {
	prevMode := a.fwEngine.RuleMode(rule).String()
	if prevMode == mode {
		return nil
	}
	a.fwEngine.SetRuleMode(rule, firewall.ParseMode(mode))
	if a.fwModes != nil {
		if err := a.fwModes.Set(rule, mode); err != nil {
			return err
		}
	}
	a.store.PutAudit(store.AuditEntry{Action: "rule-mode", Rule: rule, FromMode: prevMode, ToMode: mode})
	return nil
}

// handleFirewallMode promotes or demotes a firewall rule at runtime and persists
// the override so it survives a restart. With {"type":"vendor-key","mode":"block"}
// and no rule, every configured pattern of that secret type is promoted.
func (a *API) handleFirewallMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.fwEngine == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req fwModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Rule == "" && req.Type == "") || (req.Mode != "monitor" && req.Mode != "block") {
		http.Error(w, `Invalid payload: {"rule":"<id>","mode":"monitor|block"} or {"type":"vendor-key","mode":"block"}`, http.StatusBadRequest)
		return
	}

	ids := []string{req.Rule}
	if req.Rule == "" {
		ids = a.fwEngine.RuleIDsOfType(req.Type)
	}
	promoted := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		prev := a.fwEngine.RuleMode(id).String()
		if err := a.applyRuleMode(id, req.Mode); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		if prev != req.Mode {
			promoted = append(promoted, id)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"rule":     req.Rule,
		"type":     req.Type,
		"mode":     req.Mode,
		"promoted": promoted,
	})
}

// handleFingerprintReload re-reads the persisted fingerprints and applies them
// to the running engine, so `secure-agent fingerprint` takes effect without a
// daemon restart.
func (a *API) handleFingerprintReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.fwReload == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}
	if err := a.fwReload(); err != nil {
		http.Error(w, fmt.Sprintf("reload failed: %v", err), http.StatusInternalServerError)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "fingerprint-reload"})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

// handleFingerprintIngest scans the configured secret sources, registers their
// fingerprints (HMAC only), applies them live, and returns the labels registered.
func (a *API) handleFingerprintIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.fwIngest == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}
	labels, err := a.fwIngest()
	if err != nil {
		http.Error(w, fmt.Sprintf("ingest failed: %v", err), http.StatusInternalServerError)
		return
	}
	// Record the count only — never the labels, which carry source paths.
	a.store.PutAudit(store.AuditEntry{Action: "fingerprint-ingest", Detail: fmt.Sprintf("%d secret(s) registered", len(labels))})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "registered": labels})
}

type sourceRow struct {
	Source string `json:"source"`
	Origin string `json:"origin"` // "config" (read-only) | "user"
}

type sourceRequest struct {
	Source string `json:"source"`
	Op     string `json:"op"` // "add" | "remove"
}

// handleFirewallSources lists (GET) and edits (POST) the ingest sources — the
// files whose KEY=VALUE secrets get fingerprinted. Config-defined sources are
// read-only; only user-added sources can be removed. Every edit re-ingests so
// the fingerprint set converges on the effective source list, and is audited
// with the path (the path is the subject of the change, never a secret value).
func (a *API) handleFirewallSources(w http.ResponseWriter, r *http.Request) {
	if a.fwSources == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows := make([]sourceRow, 0, len(a.fwBaseSources))
		for _, s := range a.fwBaseSources {
			rows = append(rows, sourceRow{Source: s, Origin: "config"})
		}
		for _, s := range a.fwSources.Load() {
			rows = append(rows, sourceRow{Source: s, Origin: "user"})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)

	case http.MethodPost:
		limitBody(w, r)
		var req sourceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		req.Source = strings.TrimSpace(req.Source)
		if req.Source == "" || (req.Op != "add" && req.Op != "remove") {
			http.Error(w, `Invalid payload: {"source":"<path>","op":"add|remove"}`, http.StatusBadRequest)
			return
		}

		switch req.Op {
		case "add":
			// The daemon runs as root and reads whatever source is registered, so
			// an unvalidated path is an arbitrary-file-read primitive. Confine adds
			// to plausible user secret files: a regular file, not a system store.
			if err := validateSourcePath(req.Source); err != nil {
				http.Error(w, fmt.Sprintf("invalid source: %v", err), http.StatusBadRequest)
				return
			}
			if _, err := a.fwSources.Add(req.Source); err != nil {
				http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
				return
			}
			a.store.PutAudit(store.AuditEntry{Action: "source-add", Detail: req.Source})
		case "remove":
			removed, err := a.fwSources.Remove(req.Source)
			if err != nil {
				http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
				return
			}
			if !removed {
				http.Error(w, "not a user-added source (config sources are read-only)", http.StatusBadRequest)
				return
			}
			a.store.PutAudit(store.AuditEntry{Action: "source-remove", Detail: req.Source})
		}

		// Re-ingest so the fingerprint set tracks the effective source list. A
		// full re-ingest overwrites the persisted set, so a removed source's
		// fingerprints are purged.
		registered := 0
		if a.fwIngest != nil {
			labels, err := a.fwIngest()
			if err != nil {
				http.Error(w, fmt.Sprintf("re-ingest failed: %v", err), http.StatusInternalServerError)
				return
			}
			registered = len(labels)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "source": req.Source, "op": req.Op, "registered": registered})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// guardTokenRE bounds "agent" and "rule_id" wherever a client supplies them:
// alphanumerics plus the separators these ids actually use. Both values flow
// into the store and are echoed back in JSON, so this closes off control
// characters, path-traversal segments, and shell metacharacters at the
// boundary rather than trusting every caller downstream.
var guardTokenRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type guardDecisionRequest struct {
	Agent  string `json:"agent"`
	Tool   string `json:"tool"`
	Path   string `json:"path"`
	RuleID string `json:"rule_id"`
}

// handleGuardDecision answers a hook's prompt-mode query: a cached (agent,rule)
// decision is returned instantly; otherwise it enqueues a pending prompt and
// blocks until the menubar resolves it or the broker times out (deny).
func (a *API) handleGuardDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.guardBroker == nil {
		http.Error(w, "guard not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req guardDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.RuleID == "" ||
		!guardTokenRE.MatchString(req.Agent) || !guardTokenRE.MatchString(req.RuleID) {
		http.Error(w, `Invalid payload: {"agent","tool","path","rule_id"} (agent/rule_id must match ^[A-Za-z0-9_.-]+$)`, http.StatusBadRequest)
		return
	}
	// Per-path exceptions first: an operator-granted allow on THIS exact
	// path (or an ancestor of it) answers without prompting. Cheapest and
	// narrowest check first — one cached rule-wide allow must never widen
	// what a per-path allow does not cover.
	if a.store.GuardPathAllowed(req.Agent, req.RuleID, req.Path) {
		writeJSON(w, guard.Decision{Verdict: "allow", Scope: "always", Reason: "path-allow"})
		return
	}
	if g, ok := a.store.LookupGuardRule(req.Agent, req.RuleID); ok {
		writeJSON(w, guard.Decision{Verdict: g.Decision, Scope: "always", Reason: "cached"})
		return
	}
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&a.guardSeq, 1))
	// Push, not just poll: SSE subscribers (menubar) refetch /guard/pending
	// immediately instead of waiting out their poll interval.
	a.publishGuardEvent(event.KindGuardPrompt, req.Agent+"/"+req.RuleID)
	d := a.guardBroker.Request(guard.Pending{
		ID: id, Agent: req.Agent, Tool: req.Tool, Path: req.Path, RuleID: req.RuleID,
		// Disclose the blast radius of "allow always": the cached rule covers
		// every path this rule matches for this agent, not just this file.
		ScopeText: "Allow Always approves every path under rule \"" + req.RuleID + "\" for agent \"" + req.Agent + "\", not just this one.",
	})
	if d.Scope == "always" && d.Reason == "" {
		a.store.PutGuardRule(store.GuardRule{Agent: req.Agent, RuleID: req.RuleID, Decision: d.Verdict, Source: "prompt"})
		a.store.PutAudit(store.AuditEntry{Action: "guard-rule", Rule: req.Agent + "/" + req.RuleID, ToMode: d.Verdict})
	}
	// Downstream fleet delivery: every resolved decision (cached, prompt, or
	// timeout-deny) is observable. Payload carries no secret material — paths
	// and rule ids only, mirroring what the console already shows.
	if a.fleetSinks != nil {
		a.fleetSinks.PublishGuardDecision(map[string]any{
			"agent": req.Agent, "tool": req.Tool, "path": req.Path,
			"rule_id": req.RuleID, "verdict": d.Verdict, "scope": d.Scope,
			"reason": d.Reason, "ts": time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, d)
}

func (a *API) handleGuardPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.guardBroker == nil {
		writeJSON(w, []guard.Pending{})
		return
	}
	pending := a.guardBroker.Pending()
	// Broker.Pending() ranges a map, whose iteration order is unspecified —
	// sort oldest-first so the menubar always prompts the longest-waiting
	// request first instead of a random one.
	sort.Slice(pending, func(i, j int) bool { return pending[i].TS < pending[j].TS })
	writeJSON(w, pending)
}

type guardResolveRequest struct {
	ID      string `json:"id"`
	Verdict string `json:"verdict"` // allow | deny
	Scope   string `json:"scope"`   // once | always
}

func (a *API) handleGuardResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.guardBroker == nil {
		http.Error(w, "guard not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req guardResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" ||
		(req.Verdict != "allow" && req.Verdict != "deny") ||
		(req.Scope != "once" && req.Scope != "always") {
		http.Error(w, `Invalid payload: {"id","verdict":"allow|deny","scope":"once|always"}`, http.StatusBadRequest)
		return
	}
	ok := a.guardBroker.Resolve(req.ID, guard.Decision{Verdict: req.Verdict, Scope: req.Scope})
	if ok {
		a.publishGuardEvent(event.KindGuardResolved, req.Verdict+"/"+req.Scope)
	}
	writeJSON(w, map[string]any{"status": "ok", "resolved": ok})
}

// handleGuardPathAllow manages per-path guard exceptions: list (GET),
// add (POST {"agent","rule_id","path"}), revoke (DELETE ?agent=&rule_id=&path=).
// A path allow is narrower than a rule allow: it approves one file (and its
// descendants) instead of every path the rule matches. Mutations audited.
func (a *API) handleGuardPathAllow(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.store.ListGuardPathAllows(200))
	case http.MethodPost:
		if a.guardBroker == nil {
			http.Error(w, "guard not enabled", http.StatusServiceUnavailable)
			return
		}
		limitBody(w, r)
		var req struct {
			Agent  string `json:"agent"`
			RuleID string `json:"rule_id"`
			Path   string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.RuleID == "" || req.Path == "" ||
			!guardTokenRE.MatchString(req.Agent) || !guardTokenRE.MatchString(req.RuleID) {
			http.Error(w, `Invalid payload: {"agent","rule_id","path"} (agent/rule_id must match ^[A-Za-z0-9_.-]+$)`, http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(req.Path, "/") || len(req.Path) > 1024 || strings.Contains(req.Path, "\x00") {
			http.Error(w, "path must be an absolute filesystem path", http.StatusBadRequest)
			return
		}
		a.store.PutGuardPathAllow(store.GuardPathAllow{Agent: req.Agent, RuleID: req.RuleID, Path: req.Path})
		a.store.PutAudit(store.AuditEntry{
			Action: "guard-path-allow", Rule: req.Agent + "/" + req.RuleID,
			Detail: "allowed path " + req.Path,
		})
		a.publishGuardEvent(event.KindGuardResolved, "path-allow")
		writeJSON(w, map[string]any{"status": "ok", "agent": req.Agent, "rule_id": req.RuleID, "path": req.Path})
	case http.MethodDelete:
		agent := r.URL.Query().Get("agent")
		ruleID := r.URL.Query().Get("rule_id")
		path := r.URL.Query().Get("path")
		if agent == "" || ruleID == "" || path == "" ||
			!guardTokenRE.MatchString(agent) || !guardTokenRE.MatchString(ruleID) {
			http.Error(w, "agent, rule_id and path required", http.StatusBadRequest)
			return
		}
		removed := a.store.DeleteGuardPathAllow(agent, ruleID, path)
		if removed {
			a.store.PutAudit(store.AuditEntry{Action: "guard-path-allow-revoke", Rule: agent + "/" + ruleID, Detail: "revoked path " + path})
		}
		writeJSON(w, map[string]any{"status": "ok", "removed": removed})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGuardRules lists stored decisions (GET) and revokes one (DELETE ?agent=&rule_id=).
func (a *API) handleGuardRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.store.ListGuardRules(200))
	case http.MethodDelete:
		agent := r.URL.Query().Get("agent")
		ruleID := r.URL.Query().Get("rule_id")
		if agent == "" || ruleID == "" || !guardTokenRE.MatchString(agent) || !guardTokenRE.MatchString(ruleID) {
			http.Error(w, "agent and rule_id required, matching ^[A-Za-z0-9_.-]+$", http.StatusBadRequest)
			return
		}
		removed := a.store.DeleteGuardRule(agent, ruleID)
		if removed {
			a.store.PutAudit(store.AuditEntry{Action: "guard-rule-revoke", Rule: agent + "/" + ruleID})
		}
		writeJSON(w, map[string]any{"status": "ok", "removed": removed})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
