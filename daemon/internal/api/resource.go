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

// maxWireSamples bounds the per-session sample series in the /resources
// payload. A sparkline is ~140px wide; shipping 720 points inflated the
// snapshot to ~2 MB per fetch for pixels nobody sees. The full history stays
// in the store for episodes; the wire gets an evenly-strided downsample.
const maxWireSamples = 120

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
	// Episodes (the flight recorder) moved to /resources/episodes: ~0.5 MB of
	// historical detail the live view never renders. Emit [] (not null) so
	// existing consumers see an empty list, not a missing field.
	snapshot.Episodes = []resource.Episode{}
	for i := range snapshot.Sessions {
		snapshot.Sessions[i].Samples = downsample(snapshot.Sessions[i].Samples, maxWireSamples)
	}
	writeJSON(w, snapshot)
}

// handleResourceEpisodes serves the pressure flight recorder (historical
// episodes) on its own endpoint, so the hot /resources payload stays small.
func (a *API) handleResourceEpisodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := []resource.Episode{}
	if a.resources != nil {
		out = a.resources().Episodes
	}
	if a.store != nil {
		out = a.store.RecentResourceEpisodes(20)
	}
	writeJSON(w, out)
}

// downsample returns at most n points, evenly strided, always keeping the
// last point (the most recent sample is the one the UI labels "now").
func downsample(samples []resource.Sample, n int) []resource.Sample {
	if len(samples) <= n {
		return samples
	}
	out := make([]resource.Sample, 0, n)
	step := float64(len(samples)-1) / float64(n-1)
	for i := 0; i < n; i++ {
		out = append(out, samples[int(float64(i)*step)])
	}
	out[n-1] = samples[len(samples)-1]
	return out
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
