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

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type Killer interface {
	Kill(pid int32) error
}

type Status struct {
	Running      bool   `json:"running"`
	Uptime       string `json:"uptime"`
	ActiveAgents int    `json:"active_agents"`
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

	if err := os.MkdirAll(filepath.Dir(a.socketPath), 0o755); err != nil {
		return fmt.Errorf("failed to create socket dir: %w", err)
	}

	_ = os.Remove(a.socketPath) // remove stale socket file if present

	listener, err := net.Listen("unix", a.socketPath)
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
	mux.HandleFunc("/kill", a.handleKill)

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
