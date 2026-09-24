package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
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
		for _, p := range rep.Projects {
			if v, ok := a.store.AdvisorVerdictFor(advisor.ProjectSubjectID(p.Project), "project"); ok {
				if rep.Advice == nil {
					rep.Advice = map[string]model.AdvisorVerdict{}
				}
				rep.Advice[p.Project] = v
			}
		}
	}
	writeJSON(w, rep)
}

// handleCleanupAdvise queues one project ({"project"}: a repository path,
// or "machine" for machine-wide caches) for a cleanup plan from the local
// advisor, built from the worktree report and the clutter inventory. The
// plan is display only.
func (a *API) handleCleanupAdvise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.clutter == nil || a.worktrees == nil || a.projectAdvisor == nil {
		http.Error(w, "cleanup advice not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Project string `json:"project"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" {
		http.Error(w, `Invalid payload: {"project"}`, http.StatusBadRequest)
		return
	}
	pr := model.ProjectCleanupRequest{Project: req.Project}
	for _, repo := range a.worktrees.Report(r.Context(), false).Repos {
		if repo.Path != req.Project {
			continue
		}
		for _, wt := range repo.Worktrees {
			if wt.State == worktreehunter.StateMain {
				continue
			}
			pr.Worktrees = append(pr.Worktrees, model.ProjectWorktree{Path: wt.Path, Branch: wt.Branch, State: wt.State,
				SizeBytes: wt.SizeBytes, IdleDays: wt.IdleDays, Reasons: wt.Reasons})
		}
	}
	for _, it := range a.clutter.Report(r.Context(), false).Items {
		key := it.Project
		if key == "" {
			key = "machine"
		}
		if key == req.Project {
			pr.Clutter = append(pr.Clutter, model.ProjectClutter{Kind: it.Kind, Path: it.Path, SizeBytes: it.SizeBytes, IdleDays: it.IdleDays, Action: it.Action})
		}
	}
	if len(pr.Worktrees) == 0 && len(pr.Clutter) == 0 {
		http.Error(w, "nothing to advise on for that project", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "queued": a.projectAdvisor(pr), "subject": advisor.ProjectSubjectID(req.Project)})
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
