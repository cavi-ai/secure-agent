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
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
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
	mux.HandleFunc("/rotate", a.handleRotate)
	mux.HandleFunc("/fleet", a.handleFleet)
	mux.HandleFunc("/kill", a.handleKill)
	mux.HandleFunc("/firewall/mode", a.handleFirewallMode)
	mux.HandleFunc("/firewall/fingerprints/reload", a.handleFingerprintReload)
	mux.HandleFunc("/firewall/fingerprints/ingest", a.handleFingerprintIngest)
	mux.HandleFunc("/firewall/sources", a.handleFirewallSources)
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
	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	w.Header().Set("Content-Type", "application/json")
	flags := a.store.RecentFlags(limit)
	json.NewEncoder(w).Encode(flags)
}

func (a *API) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	w.Header().Set("Content-Type", "application/json")
	events := a.store.RecentEvents(limit)
	json.NewEncoder(w).Encode(events)
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

type rotateRequest struct {
	IncidentID string `json:"incident_id"`
	ItemID     string `json:"item_id"`
}

type rotateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	ItemID  string `json:"item_id"`
}

func (a *API) handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IncidentID == "" || req.ItemID == "" {
		http.Error(w, "Invalid payload: incident_id and item_id required", http.StatusBadRequest)
		return
	}

	inc, err := a.store.GetIncident(req.IncidentID)
	if err != nil || inc == nil {
		http.Error(w, "Incident not found", http.StatusNotFound)
		return
	}

	var targetItem *model.RotateItem
	for _, item := range inc.RotateList {
		if item.ID == req.ItemID {
			targetItem = &item
			break
		}
	}

	if targetItem == nil {
		http.Error(w, "Rotate item not found in incident", http.StatusNotFound)
		return
	}

	rotator := intel.NewRotator()
	msg, err := rotator.Execute(*targetItem)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(rotateResponse{
			Success: false,
			Message: err.Error(),
			ItemID:  req.ItemID,
		})
		return
	}

	json.NewEncoder(w).Encode(rotateResponse{
		Success: true,
		Message: msg,
		ItemID:  req.ItemID,
	})
}
