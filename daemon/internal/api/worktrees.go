package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentask"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
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
	rep := a.worktrees.Report(r.Context(), refresh)
	rep.Advice = a.worktreeNotes(rep)
	rep.Asks = a.latestAsks()
	if a.store != nil {
		t := a.store.CleanupTotals(time.Now())
		rep.Reclaimed = &t
	}
	writeJSON(w, rep)
}

// latestAsks maps each worktree path to its newest agent ask.
func (a *API) latestAsks() map[string]model.AgentAsk {
	if a.store == nil {
		return nil
	}
	out := map[string]model.AgentAsk{}
	for _, ask := range a.store.AgentAsks(500) {
		if _, seen := out[ask.Path]; !seen {
			out[ask.Path] = ask
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// handleWorktreeAsk resumes the conversation of the agent that worked in a
// keep or review worktree ({"path"}) and asks it to open a pull request for
// work worth keeping or to say the worktree can go. The answer arrives
// later in GET /worktrees/asks and the report's asks.
func (a *API) handleWorktreeAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil || a.asker == nil {
		http.Error(w, "asking agents is not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !filepath.IsAbs(req.Path) {
		http.Error(w, `Invalid payload: {"path"} (absolute)`, http.StatusBadRequest)
		return
	}
	row, repo, err := a.worktrees.Inspect(r.Context(), req.Path)
	switch {
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	case row.State != worktreehunter.StateKeep && row.State != worktreehunter.StateReview:
		http.Error(w, "only a keep or review worktree has work to sort out; this one is "+row.State, http.StatusConflict)
		return
	}
	ask, err := a.asker.Ask(agentask.Request{Path: row.Path, Repo: repo, Branch: row.Branch, State: row.State, Reasons: row.Reasons})
	switch {
	case errors.Is(err, agentask.ErrNoSession):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, agentask.ErrBusy):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		writeJSON(w, map[string]any{"status": "ok", "ask": ask})
	}
}

// handleWorktreeAsks lists agent asks, newest first.
func (a *API) handleWorktreeAsks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "store not wired", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, a.store.AgentAsks(queryInt(r.URL.Query().Get("limit"), 50)))
}

// handleCleanupLedger serves the cleanup ledger: what was removed and the
// bytes it gave back, newest first, with all-time and 30-day totals.
func (a *API) handleCleanupLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "store not wired", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{
		"totals":  a.store.CleanupTotals(time.Now()),
		"entries": a.store.CleanupLog(queryInt(r.URL.Query().Get("limit"), 100)),
	})
}

// worktreeNotes looks up the stored advisor note for each row at its current
// HEAD. rep is the handler's copy: the map is new, the cached scan untouched.
func (a *API) worktreeNotes(rep worktreehunter.ScanReport) map[string]model.AdvisorVerdict {
	if a.store == nil {
		return nil
	}
	notes := map[string]model.AdvisorVerdict{}
	for _, repo := range rep.Repos {
		for _, wt := range repo.Worktrees {
			if wt.Head == "" || wt.State == worktreehunter.StateMain {
				continue
			}
			if v, ok := a.store.AdvisorVerdictFor(advisor.WorktreeSubjectID(wt.Path, wt.Head), "worktree"); ok {
				notes[wt.Path] = v
			}
		}
	}
	if len(notes) == 0 {
		return nil
	}
	return notes
}

// handleWorktreeAdvise queues one worktree ({"path"}) for an advisory note
// from the local model. The note is displayed beside the row; it never
// changes the verdict or what Remove accepts.
func (a *API) handleWorktreeAdvise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil || a.worktreeAdvisor == nil {
		http.Error(w, "worktree advice not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !filepath.IsAbs(req.Path) {
		http.Error(w, `Invalid payload: {"path"} (absolute)`, http.StatusBadRequest)
		return
	}
	adv, err := a.worktrees.AdviceRequest(r.Context(), req.Path)
	switch {
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case errors.Is(err, worktreehunter.ErrNothingToAdvise):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "queued": a.worktreeAdvisor(adv), "subject": advisor.WorktreeSubjectID(adv.Path, adv.Head)})
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
// a refusal answers 409 with that verdict's state and reasons. With
// "async": true it answers 202 at once and GET /worktrees reports the
// removal's steps and outcome under "removals".
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
		Async bool   `json:"async"`
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
	if req.Async {
		rm, err := a.worktrees.StartRemove(req.Path)
		if errors.Is(err, worktreehunter.ErrRemoving) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "removal": rm})
		return
	}
	row, err := a.worktrees.Remove(r.Context(), req.Path)
	var refused *worktreehunter.NotRemovableError
	switch {
	case errors.Is(err, worktreehunter.ErrRemoving):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.As(err, &refused):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "not removable", "state": refused.Row.State, "reasons": refused.Row.Reasons})
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "removed": row.Path, "branch": row.Branch, "reasons": row.Reasons,
			"bytes": row.SizeBytes, "bytes_partial": row.SizePartial})
	}
}

// worktreePath decodes {"path"} for the worktree folder actions.
func (a *API) worktreePath(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return "", false
	}
	limitBody(w, r)
	var req filePathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !filepath.IsAbs(req.Path) {
		http.Error(w, `Invalid payload: {"path": "<absolute path>"}`, http.StatusBadRequest)
		return "", false
	}
	return filepath.Clean(req.Path), true
}

// handleWorktreeReveal serves POST /worktrees/reveal: Finder selects a
// folder the current worktree report lists.
func (a *API) handleWorktreeReveal(w http.ResponseWriter, r *http.Request) {
	p, ok := a.worktreePath(w, r)
	if !ok {
		return
	}
	if !a.worktrees.Listed(p) {
		http.Error(w, "not a folder the worktree report lists", http.StatusNotFound)
		return
	}
	if _, err := os.Stat(p); err != nil {
		http.Error(w, "the folder no longer exists", http.StatusGone)
		return
	}
	if err := a.openPath("-R", p); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			http.Error(w, "opening folders is supported on macOS only", http.StatusNotImplemented)
			return
		}
		http.Error(w, "open failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "worktree-reveal", Detail: p})
	writeJSON(w, map[string]bool{"ok": true})
}

// handleWorktreeReconnect serves POST /worktrees/reconnect: `git worktree
// repair` in the repository that still records an orphan folder.
func (a *API) handleWorktreeReconnect(w http.ResponseWriter, r *http.Request) {
	p, ok := a.worktreePath(w, r)
	if !ok {
		return
	}
	repo, err := a.worktrees.Reconnect(r.Context(), p)
	switch {
	case errors.Is(err, worktreehunter.ErrNotOrphan):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, worktreehunter.ErrNoReconnect):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "repo": repo})
	}
}

// handleWorktreeTrash serves POST /worktrees/trash: an orphan folder goes
// to the Trash on its volume.
func (a *API) handleWorktreeTrash(w http.ResponseWriter, r *http.Request) {
	p, ok := a.worktreePath(w, r)
	if !ok {
		return
	}
	res, err := a.worktrees.TrashOrphan(r.Context(), p)
	switch {
	case errors.Is(err, worktreehunter.ErrNotOrphan):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "result": res})
	}
}
