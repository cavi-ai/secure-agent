package api

import (
	"io"
	"net/http"
)

// serveSessionReport serves what one session did — tools, models, spend,
// files, hosts, guard decisions, findings, secret-rule hits and the opening
// timeline — as JSON (default) or markdown. Read-level.
//
//	GET /sessions/{id}/report?format=json|md
func (a *API) serveSessionReport(w http.ResponseWriter, r *http.Request, id string) {
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "md" {
		http.Error(w, "format must be json or md", http.StatusBadRequest)
		return
	}
	rep, ok := a.store.SessionReport(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if format == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = io.WriteString(w, renderSessionMarkdown(rep))
		return
	}
	writeJSON(w, rep)
}
