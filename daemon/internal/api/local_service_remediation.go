package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/modelservice"
	"github.com/cavi-ai/secure-agent/internal/modelruntime"
)

func (a *API) serviceManager() *modelservice.Manager {
	return a.modelServices
}

func (a *API) handleLocalServiceRemediation(w http.ResponseWriter, r *http.Request) {
	if a.serviceManager() == nil {
		http.Error(w, "model service remediation requires a saved configuration", 503)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Action string `json:"action"`
		Source string `json:"source"`
		ID     string `json:"id"`
		Hash   string `json:"preview_hash"`
		Label  string `json:"label"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid remediation request", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	switch input.Action {
	case "preview":
		if input.Source == "" || input.ID != "" || input.Hash != "" || input.Label != "" {
			http.Error(w, "preview requires only a service definition path", 400)
			return
		}
		preview, err := a.serviceManager().Preview(ctx, input.Source)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		writeJSON(w, preview)
	case "apply":
		if input.ID == "" || input.Hash == "" || input.Source != "" || input.Label != "" {
			http.Error(w, "apply requires only the displayed preview identity", 400)
			return
		}
		receipt, err := a.serviceManager().Apply(ctx, input.ID, input.Hash)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			writeJSON(w, map[string]any{"error": err.Error(), "receipt": receipt})
			return
		}
		writeJSON(w, receipt)
	case "rollback":
		if input.Label == "" || input.Source != "" || input.ID != "" || input.Hash != "" {
			http.Error(w, "rollback requires only a service label", 400)
			return
		}
		receipt, err := a.serviceManager().Rollback(ctx, input.Label)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			writeJSON(w, map[string]any{"error": err.Error(), "receipt": receipt})
			return
		}
		writeJSON(w, receipt)
	default:
		http.Error(w, "unknown remediation action", 400)
	}
}

func (a *API) handleLocalServiceReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	if a.modelServices == nil {
		http.Error(w, "model service remediation unavailable", 503)
		return
	}
	query := r.URL.Query()
	if len(query) != 1 || len(query["label"]) != 1 {
		http.Error(w, "one service label is required", 400)
		return
	}
	receipt, err := a.modelServices.Status(query.Get("label"))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	writeJSON(w, receipt)
}

func newServiceManager(path string) *modelservice.Manager {
	if path == "" {
		return nil
	}
	return modelservice.New(path, func() string { binary, _ := modelruntime.Find(); return binary })
}
