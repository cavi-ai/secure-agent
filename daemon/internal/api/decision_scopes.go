package api

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// decisionScopeView is the GET body. Applicability is computed for the
// response and is not a stored column.
type decisionScopeView struct {
	model.DecisionScope
	Applicability model.ScopeApplicability `json:"applicability"`
}

func (a *API) handleDecisionScopes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		scopes, err := a.store.ListDecisionScopes()
		if err != nil {
			http.Error(w, "Permissions unavailable", 503)
			return
		}
		now := time.Now()
		views := make([]decisionScopeView, len(scopes))
		for i, scope := range scopes {
			views[i] = decisionScopeView{DecisionScope: scope, Applicability: scope.Applicability(now)}
		}
		writeJSON(w, views)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if !guardTokenRE.MatchString(id) {
			http.Error(w, "Permission id required", 400)
			return
		}
		err := a.store.RevokeDecisionScope(id)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Permission not found", 404)
			return
		}
		if err != nil {
			http.Error(w, "Revocation could not be saved", 503)
			return
		}
		writeJSON(w, map[string]any{"revoked": true, "id": id})
	default:
		http.Error(w, "Method not allowed", 405)
	}
}
