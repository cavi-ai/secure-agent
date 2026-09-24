package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
)

// handleCleanup serves the clutter inventory: .tmp and .quarantine
// directories, build output, tool and app caches, with sizes, last touched,
// the project each belongs to and the ledger's reclaimed totals.
func (a *API) handleCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.clutter == nil {
		http.Error(w, "cleanup inventory not enabled", http.StatusServiceUnavailable)
		return
	}
	rep := a.clutter.Report(r.Context(), r.URL.Query().Get("refresh") == "1")
	if a.store != nil {
		t := a.store.CleanupTotals(time.Now())
		rep.Reclaimed = &t
	}
	writeJSON(w, rep)
}

// handleCleanupTrash moves one inventory item ({"path"}) to the Trash on
// its volume.
func (a *API) handleCleanupTrash(w http.ResponseWriter, r *http.Request) {
	a.cleanupAction(w, r, "path", a.clutterTrash)
}

// handleCleanupClean runs one tool cache's own clean command ({"name"}).
func (a *API) handleCleanupClean(w http.ResponseWriter, r *http.Request) {
	a.cleanupAction(w, r, "name", a.clutterClean)
}

func (a *API) clutterTrash(r *http.Request, key string) (clutter.ClutterResult, error) {
	return a.clutter.Trash(r.Context(), key)
}

func (a *API) clutterClean(r *http.Request, key string) (clutter.ClutterResult, error) {
	return a.clutter.Clean(r.Context(), key)
}

func (a *API) cleanupAction(w http.ResponseWriter, r *http.Request, field string, act func(*http.Request, string) (clutter.ClutterResult, error)) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.clutter == nil {
		http.Error(w, "cleanup inventory not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req[field] == "" {
		http.Error(w, `Invalid payload: {"`+field+`"}`, http.StatusBadRequest)
		return
	}
	res, err := act(r, req[field])
	switch {
	case errors.Is(err, clutter.ErrNotInInventory):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, clutter.ErrChanged):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "result": res})
	}
}
