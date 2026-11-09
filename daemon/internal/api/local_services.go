package api

import (
	"net/http"
	"net/url"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func (a *API) localServiceTargets(explicit []string) ([]string, error) {
	if len(explicit) != 0 {
		return explicit, nil
	}
	cfg, err := config.LoadStrict(a.configPath)
	if err != nil {
		return nil, err
	}
	targets := localservice.DefaultEndpoints()
	if cfg.Advisor.Enabled {
		if !cfg.Advisor.Managed {
			targets = append(targets, cfg.Advisor.Endpoint)
		}
		if cfg.Advisor.ClassifierEndpoint != "" {
			targets = append(targets, cfg.Advisor.ClassifierEndpoint)
		}
	}
	if cfg.SystemAgent.Enabled {
		targets = append(targets, cfg.SystemAgent.Endpoint)
	}
	if cfg.DirectoryGuard.ShellReview.Enabled {
		targets = append(targets, cfg.DirectoryGuard.ShellReview.Endpoint)
	}
	if a.localModelEndpoint != nil {
		if endpoint := a.localModelEndpoint(); endpoint != "" {
			targets = append(targets, endpoint)
		}
	}
	return targets, nil
}

func (a *API) handleLocalServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid assessment query", http.StatusBadRequest)
		return
	}
	for key := range query {
		if key != "endpoint" {
			http.Error(w, "only endpoint query parameters are supported", http.StatusBadRequest)
			return
		}
	}
	targets, err := a.localServiceTargets(query["endpoint"])
	if err != nil {
		http.Error(w, "configured model endpoints unavailable", http.StatusServiceUnavailable)
		return
	}
	report, err := localservice.Assess(r.Context(), targets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, report)
}
