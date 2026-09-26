package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// flagExpectedPattern is the expected-pattern entry a read-then-connect flag
// stands for; false when its evidence does not record who read the file.
func flagExpectedPattern(f model.Flag) (correlate.ExpectedPattern, bool) {
	read, conn := evidenceOfKind(f, "read"), evidenceOfKind(f, "connect")
	if f.Rule != readConnectRule || f.Agent == "" || read == nil || conn == nil {
		return correlate.ExpectedPattern{}, false
	}
	toolRead := read.Sub == "agent tool read"
	host, _ := splitHostPort(conn.Label)
	if host == "" || (read.Exe == "" && !toolRead) {
		return correlate.ExpectedPattern{}, false
	}
	p := correlate.ExpectedPattern{
		Agent:  f.Agent,
		Reader: correlate.ReaderLabel(read.Exe, toolRead),
		Path:   read.Label,
		Dest:   correlate.DestLabel(host),
	}
	p.Key = correlate.ReadConnectKey(p.Agent, p.Reader, p.Path, p.Dest)
	return p, true
}

// expectAction offers marking f's pattern expected, unless it already is.
func (a *API) expectAction(f model.Flag) (model.ExplainAction, bool) {
	p, ok := flagExpectedPattern(f)
	if !ok || a.expected == nil || a.expected.Has(p.Key) {
		return model.ExplainAction{}, false
	}
	file := displayPath(p.Path, strings.TrimRight(explainHome(), "/"))
	return model.ExplainAction{
		ID: "expect", Label: "Expected: " + p.Reader + " → " + p.Dest,
		Consequence: "Later reads of " + file + " by " + p.Reader + " followed by a connection to " + p.Dest +
			" are counted, not flagged; open flags of this pattern are marked reviewed. A new reader, file or destination still flags. Forget it under Policy.",
		Method: http.MethodPost, Path: "/expected",
		Body: map[string]any{"flag_id": f.ID},
	}, true
}

// handleExpected lists (GET), adds from a flag (POST {"flag_id"}) and
// forgets (DELETE ?key=) the read-then-connect patterns the operator marked
// expected.
func (a *API) handleExpected(w http.ResponseWriter, r *http.Request) {
	if a.expected == nil {
		http.Error(w, "expected patterns not enabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.expected.List())
	case http.MethodPost:
		limitBody(w, r)
		var req struct {
			FlagID string `json:"flag_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FlagID == "" {
			http.Error(w, `Invalid payload: {"flag_id":"<id>"}`, http.StatusBadRequest)
			return
		}
		f, ok := a.store.GetFlag(req.FlagID)
		if !ok {
			http.Error(w, "unknown flag", http.StatusNotFound)
			return
		}
		p, ok := flagExpectedPattern(f)
		if !ok {
			http.Error(w, "flag is not a read-then-connect flag with a recorded reader", http.StatusUnprocessableEntity)
			return
		}
		p.CreatedAt = time.Now().UTC()
		stored, err := a.expected.Add(p)
		if err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		acked := a.acknowledgeExpected(stored.Key)
		a.recordLabel(model.OperatorLabel{Kind: "flag", Rule: readConnectRule, Agent: stored.Agent, Pattern: stored.Path, Label: "ok", Source: "expect"})
		a.store.PutAudit(store.AuditEntry{
			Action: "expect-add", Rule: readConnectRule,
			Detail: fmt.Sprintf("expected %s reading %s then reaching %s for %s (%d open flags acknowledged)", stored.Reader, stored.Path, stored.Dest, stored.Agent, acked),
		})
		writeJSON(w, stored)
	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "DELETE requires ?key=<pattern key>", http.StatusBadRequest)
			return
		}
		removed, err := a.expected.Remove(key)
		if err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		if !removed {
			http.Error(w, "unknown pattern", http.StatusNotFound)
			return
		}
		a.store.PutAudit(store.AuditEntry{Action: "expect-remove", Rule: readConnectRule, Detail: "forgot expected pattern " + key})
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// acknowledgeExpected acknowledges every open read-then-connect flag whose
// pattern is key; returns how many.
func (a *API) acknowledgeExpected(key string) int {
	open := a.store.QueryFlags(store.FlagFilter{Rule: readConnectRule, Unacted: true, Limit: math.MaxInt32})
	var ids []string
	for _, f := range open {
		if p, ok := flagExpectedPattern(f); ok && p.Key == key {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	return a.store.AcknowledgeFlags(ids)
}
