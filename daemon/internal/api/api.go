package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
	"golang.org/x/sys/unix"
)

type Killer interface {
	Kill(pid int32) error
}

type AgentSummary struct {
	PID     int32  `json:"pid"`
	Name    string `json:"name"`
	ExePath string `json:"exe_path,omitempty"`
	CWD     string `json:"cwd,omitempty"`
}

type Status struct {
	Running           bool           `json:"running"`
	Uptime            string         `json:"uptime"`
	ActiveAgents      int            `json:"active_agents"`
	Agents            []AgentSummary `json:"agents"`
	ProxyEnabled      bool           `json:"proxy_enabled"`
	ProxyPort         int            `json:"proxy_port"`
	UninspectedEgress int            `json:"uninspected_egress"`

	FirewallStats map[string]firewall.RuleStat `json:"firewall_stats,omitempty"`
	// Collectors reports each supervised worker's health so a dead or abandoned
	// collector cannot appear healthy just because the daemon process is up.
	Collectors []supervise.Health `json:"collectors,omitempty"`
}

type StatusFunc func() Status

type API struct {
	socketPath string
	store      *store.Store
	killer     Killer
	statusFn   StatusFunc

	fwEngine      *firewall.Engine
	fwModes       *firewall.ModeStore
	fwReload      func() error
	fwIngest      func() ([]string, error)
	fwSources     *firewall.SourceStore
	fwBaseSources []string

	guardBroker *guard.Broker
	guardSeq    uint64
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

	mux := http.NewServeMux()
	mux.HandleFunc("/status", a.handleStatus)
	mux.HandleFunc("/flags", a.handleFlags)
	mux.HandleFunc("/events", a.handleEvents)
	mux.HandleFunc("/incidents", a.handleIncidents)
	mux.HandleFunc("/audit", a.handleAudit)
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

	server := &http.Server{Handler: mux}

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
	w.Header().Set("Content-Type", "application/json")
	st := a.statusFn()
	json.NewEncoder(w).Encode(st)
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(inc)
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
	json.NewEncoder(w).Encode(incidents)
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

type killRequest struct {
	PID int32 `json:"pid"`
}

func (a *API) handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req killRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PID <= 0 {
		http.Error(w, "Invalid pid", http.StatusBadRequest)
		return
	}

	if err := a.killer.Kill(req.PID); err != nil {
		http.Error(w, fmt.Sprintf("Kill failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "pid": req.PID})
}

type fwModeRequest struct {
	Rule string `json:"rule"`
	Mode string `json:"mode"` // "monitor" | "block"
}

// handleFirewallMode promotes or demotes a firewall rule at runtime and persists
// the override so it survives a restart.
func (a *API) handleFirewallMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.fwEngine == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}
	var req fwModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Rule == "" || (req.Mode != "monitor" && req.Mode != "block") {
		http.Error(w, `Invalid payload: {"rule":"<id>","mode":"monitor|block"}`, http.StatusBadRequest)
		return
	}

	// Capture the prior mode before mutating so the audit row is meaningful
	// ("monitor → block" is the record worth keeping).
	prevMode := a.fwEngine.RuleMode(req.Rule).String()
	a.fwEngine.SetRuleMode(req.Rule, firewall.ParseMode(req.Mode))
	if a.fwModes != nil {
		if err := a.fwModes.Set(req.Rule, req.Mode); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
	}
	a.store.PutAudit(store.AuditEntry{Action: "rule-mode", Rule: req.Rule, FromMode: prevMode, ToMode: req.Mode})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "rule": req.Rule, "mode": req.Mode})
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
	var req guardDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.RuleID == "" ||
		!guardTokenRE.MatchString(req.Agent) || !guardTokenRE.MatchString(req.RuleID) {
		http.Error(w, `Invalid payload: {"agent","tool","path","rule_id"} (agent/rule_id must match ^[A-Za-z0-9_.-]+$)`, http.StatusBadRequest)
		return
	}
	if g, ok := a.store.LookupGuardRule(req.Agent, req.RuleID); ok {
		writeJSON(w, guard.Decision{Verdict: g.Decision, Scope: "always", Reason: "cached"})
		return
	}
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&a.guardSeq, 1))
	d := a.guardBroker.Request(guard.Pending{
		ID: id, Agent: req.Agent, Tool: req.Tool, Path: req.Path, RuleID: req.RuleID,
	})
	if d.Scope == "always" && d.Reason == "" {
		a.store.PutGuardRule(store.GuardRule{Agent: req.Agent, RuleID: req.RuleID, Decision: d.Verdict, Source: "prompt"})
		a.store.PutAudit(store.AuditEntry{Action: "guard-rule", Rule: req.Agent + "/" + req.RuleID, ToMode: d.Verdict})
	}
	writeJSON(w, d)
}

func (a *API) handleGuardPending(w http.ResponseWriter, r *http.Request) {
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
	if r.Method != http.MethodPost || a.guardBroker == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req guardResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		(req.Verdict != "allow" && req.Verdict != "deny") ||
		(req.Scope != "once" && req.Scope != "always") {
		http.Error(w, `Invalid payload: {"id","verdict":"allow|deny","scope":"once|always"}`, http.StatusBadRequest)
		return
	}
	ok := a.guardBroker.Resolve(req.ID, guard.Decision{Verdict: req.Verdict, Scope: req.Scope})
	writeJSON(w, map[string]any{"status": "ok", "resolved": ok})
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
