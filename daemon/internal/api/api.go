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
}

func New(socketPath string, store *store.Store, killer Killer, statusFn StatusFunc) *API {
	return &API{
		socketPath: socketPath,
		store:      store,
		killer:     killer,
		statusFn:   statusFn,
	}
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
	mux.HandleFunc("/rotate", a.handleRotate)
	mux.HandleFunc("/fleet", a.handleFleet)
	mux.HandleFunc("/kill", a.handleKill)
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
