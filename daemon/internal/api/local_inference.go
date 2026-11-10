package api

import "net/http"

func (a *API) handleLocalInference(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "local inference accepts no query parameters", 400)
		return
	}
	if a.localInference == nil {
		http.Error(w, "local inference monitoring is unavailable", 503)
		return
	}
	writeJSON(w, a.localInference.Snapshot())
}
