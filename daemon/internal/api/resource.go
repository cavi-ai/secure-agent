package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func (a *API) handleResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.resources == nil {
		http.Error(w, "resource telemetry not enabled", http.StatusServiceUnavailable)
		return
	}
	snapshot := a.resources()
	if a.store != nil {
		snapshot.Episodes = a.store.RecentResourceEpisodes(20)
	}
	writeJSON(w, snapshot)
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
		ID         string `json:"id"`
		SessionKey string `json:"session_key"`
		Decision   string `json:"decision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	var err error
	if req.Decision == "resume" {
		err = a.resourceControl.Resume(req.SessionKey, time.Now())
	} else {
		err = a.resourceControl.Resolve(req.ID, req.Decision, time.Now())
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	rule := req.ID
	if rule == "" {
		rule = req.SessionKey
	}
	a.store.PutAudit(store.AuditEntry{Action: "resource-control", Rule: rule, ToMode: req.Decision})
	writeJSON(w, map[string]string{"status": "ok", "id": req.ID, "session_key": req.SessionKey, "decision": req.Decision})
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

// BudgetSummary returns the controller's compact budget posture (counts only)
// for the fleet heartbeat and the console header. Zero value when no
// controller is wired (unit tests, older integrations).
func (a *API) BudgetSummary() resource.BudgetSummary {
	if a.resourceControl == nil {
		return resource.BudgetSummary{}
	}
	snap := a.resourceControl.Snapshot()
	if snap.Control == nil {
		return resource.BudgetSummary{}
	}
	return snap.Control.Budget
}
