package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func (a *API) handleIncidentRemediation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req model.IncidentRemediationRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Invalid remediation request", 400)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "Invalid remediation request", 400)
		return
	}
	inc, err := a.store.ReportIncidentRemediation(req)
	switch {
	case errors.Is(err, store.ErrInvalidIncidentRemediation):
		http.Error(w, "Invalid remediation step or status", 400)
	case errors.Is(err, store.ErrStaleIncidentRemediation):
		http.Error(w, "Incident changed; review its latest evidence and steps", 409)
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "Incident not found", 404)
	case err != nil:
		http.Error(w, "Remediation update unavailable", 503)
	default:
		a.store.PutAudit(store.AuditEntry{Action: "incident-remediation", Rule: inc.ID, ToMode: req.Status, Detail: "step=" + req.StepID + "; operator reported; verification unverified"})
		writeJSON(w, map[string]any{"status": "ok", "incident": inc})
	}
}
