package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
)

// The system agent behind the console's Agent tab (docs/SYSTEM_AGENT.md).
// Every route is NoAgent: an agent process cannot chat with it, save a plan
// or dispatch a harness.

// AgentChat is what GET /agent/chat answers.
type AgentChat struct {
	Messages []model.SysAgentMessage `json:"messages"`
	Chatting bool                    `json:"chatting"`
}

// sysAgentReady answers 503 when the daemon was built without the agent.
func (a *API) sysAgentReady(w http.ResponseWriter) bool {
	if a.sysAgent == nil {
		http.Error(w, "the system agent is not wired", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// writeSysAgentError maps the agent's errors onto status codes.
func writeSysAgentError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, sysagent.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, sysagent.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, sysagent.ErrSecret):
		code = http.StatusUnprocessableEntity
	case errors.Is(err, sysagent.ErrDisabled), errors.Is(err, sysagent.ErrBusy), errors.Is(err, sysagent.ErrUnavailable):
		code = http.StatusConflict
	}
	http.Error(w, err.Error(), code)
}

func (a *API) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.sysAgentReady(w) {
		return
	}
	writeJSON(w, a.sysAgent.Status(r.Context()))
}

func (a *API) handleAgentSkills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, sysagent.Skills())
}

// handleAgentChat: GET the conversation, POST a message (the reply lands
// asynchronously; poll GET until chatting is false), DELETE clears it.
func (a *API) handleAgentChat(w http.ResponseWriter, r *http.Request) {
	if !a.sysAgentReady(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, AgentChat{Messages: a.sysAgent.Messages(200), Chatting: a.sysAgent.Chatting()})
	case http.MethodPost:
		limitBody(w, r)
		var in sysagent.ChatInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, `Invalid payload: {"message", "harness", "workdir"}`, http.StatusBadRequest)
			return
		}
		m, err := a.sysAgent.Send(in)
		if err != nil {
			writeSysAgentError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": m})
	case http.MethodDelete:
		if err := a.sysAgent.Clear(); err != nil {
			writeSysAgentError(w, err)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAgentPlans: GET plans with their readiness, POST saves one (new,
// from a reply's proposal, or an edit), DELETE ?id= removes one.
func (a *API) handleAgentPlans(w http.ResponseWriter, r *http.Request) {
	if !a.sysAgentReady(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.sysAgent.Plans(r.Context(), 200))
	case http.MethodPost:
		limitBody(w, r)
		var in sysagent.PlanInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, `Invalid payload: {"id"|"message_id", "title", "harness", "mode", "workdir", "task", "steps", "skills", "model"}`, http.StatusBadRequest)
			return
		}
		p, err := a.sysAgent.SavePlan(in)
		if err != nil {
			writeSysAgentError(w, err)
			return
		}
		writeJSON(w, map[string]any{"plan": p})
	case http.MethodDelete:
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "id must be a plan id", http.StatusBadRequest)
			return
		}
		if err := a.sysAgent.DeletePlan(id); err != nil {
			writeSysAgentError(w, err)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAgentDispatch runs a plan's harness: headless (202, poll
// /agent/runs) or in a terminal.
func (a *API) handleAgentDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.sysAgentReady(w) {
		return
	}
	limitBody(w, r)
	var in sysagent.DispatchInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PlanID <= 0 {
		http.Error(w, `Invalid payload: {"plan_id", "mode", "workdir", "model"}`, http.StatusBadRequest)
		return
	}
	run, err := a.sysAgent.Dispatch(r.Context(), in)
	if err != nil {
		writeSysAgentError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"run": run})
}

func (a *API) handleAgentRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.sysAgentReady(w) {
		return
	}
	writeJSON(w, a.sysAgent.Runs(50))
}
