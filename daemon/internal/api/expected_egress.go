package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type expectedEgressRequest struct {
	EpisodeID string `json:"episode_id"`
	Kind      string `json:"kind"`
}

// handleExpectedEgress only accepts an episode ID and a decision kind. The
// destination and activity scope always come from the server's observation.
func (a *API) handleExpectedEgress(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, err := a.store.ListExpectedEgressRulesResult()
		if err != nil {
			http.Error(w, "expected egress rules unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"rules": rules})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req expectedEgressRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid expected-egress request", http.StatusBadRequest)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			http.Error(w, "invalid expected-egress request", http.StatusBadRequest)
			return
		}
		if req.Kind != "destination" && req.Kind != "scope" {
			http.Error(w, "invalid rule kind", http.StatusBadRequest)
			return
		}
		episode, ok, err := a.store.GetEgressEpisodeResult(req.EpisodeID)
		if err != nil {
			http.Error(w, "egress episode unavailable", http.StatusServiceUnavailable)
			return
		}
		if !ok {
			http.Error(w, "episode not found", http.StatusNotFound)
			return
		}
		if episode.Scope.Agent == "" || episode.Scope.Agent == "unknown" {
			http.Error(w, "agent identity unavailable", http.StatusBadRequest)
			return
		}
		if req.Kind == "scope" && !episode.ScopeComplete {
			http.Error(w, "complete activity scope required", http.StatusBadRequest)
			return
		}
		rule := store.ExpectedEgressRule{Agent: episode.Scope.Agent, Kind: req.Kind}
		if req.Kind == "scope" {
			rule.ExePath, rule.Harness, rule.Workspace = episode.Scope.ExePath, episode.Scope.Harness, episode.Scope.Workspace
		} else {
			rule.Host, rule.Protocol, rule.Port = episode.Host, episode.Protocol, episode.Port
		}
		saved, err := a.store.CreateExpectedEgressRule(rule)
		if err != nil {
			http.Error(w, "invalid observed destination or scope", http.StatusBadRequest)
			return
		}
		a.store.PutAudit(store.AuditEntry{Action: "expected-egress-create", Rule: saved.ID, ToMode: saved.Kind, Detail: "operator decision from observed episode"})
		writeJSON(w, saved)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
			http.Error(w, "invalid rule id", http.StatusBadRequest)
			return
		}
		if err := a.store.RevokeExpectedEgressRule(id); err != nil {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		a.store.PutAudit(store.AuditEntry{Action: "expected-egress-revoke", Rule: id, ToMode: "revoked", Detail: "operator decision"})
		writeJSON(w, map[string]string{"status": "revoked", "id": id})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
