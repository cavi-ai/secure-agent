package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

// handleWorktrees serves the worktree hunter's report. ?refresh=1 asks for a
// rescan (the hunter still answers from a scan finished moments ago).
func (a *API) handleWorktrees(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	writeJSON(w, a.worktrees.Report(r.Context(), refresh))
}

// handleWorktreeRepos edits the saved repo list: {"path"} adds the repository
// containing path (unhiding it), {"path", "hidden": true} hides it.
func (a *API) handleWorktreeRepos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path   string `json:"path"`
		Hidden bool   `json:"hidden"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, `Invalid payload: {"path", "hidden"?}`, http.StatusBadRequest)
		return
	}
	if req.Hidden {
		if !a.worktrees.HideRepo(req.Path) {
			http.Error(w, "repository is not on the saved list", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "hidden": true})
		return
	}
	main, err := a.worktrees.AddRepo(req.Path)
	switch {
	case errors.Is(err, worktreehunter.ErrNotRepo):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "path": main})
}

// handleWorktreeRemove removes one worktree ({"path"}) or prunes a
// repository's missing ones ({"repo", "prune": true}). The hunter inspects
// the worktree again first and removes it only on a fresh remove verdict;
// a refusal answers 409 with that verdict's state and reasons.
func (a *API) handleWorktreeRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path  string `json:"path"`
		Repo  string `json:"repo"`
		Prune bool   `json:"prune"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Prune && req.Repo == "") || (!req.Prune && req.Path == "") {
		http.Error(w, `Invalid payload: {"path"} or {"repo", "prune": true}`, http.StatusBadRequest)
		return
	}
	target := req.Path
	if req.Prune {
		target = req.Repo
	}
	if !filepath.IsAbs(target) {
		http.Error(w, "path must be absolute", http.StatusBadRequest)
		return
	}
	if req.Prune {
		pruned, err := a.worktrees.Prune(r.Context(), req.Repo)
		switch {
		case errors.Is(err, worktreehunter.ErrNotRepo):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, worktreehunter.ErrNothingToPrune):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			writeJSON(w, map[string]any{"status": "ok", "pruned": pruned})
		}
		return
	}
	row, err := a.worktrees.Remove(r.Context(), req.Path)
	var refused *worktreehunter.NotRemovableError
	switch {
	case errors.As(err, &refused):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "not removable", "state": refused.Row.State, "reasons": refused.Row.Reasons})
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "removed": row.Path, "branch": row.Branch, "reasons": row.Reasons})
	}
}
