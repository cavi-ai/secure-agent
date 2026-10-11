package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/cavi-ai/secure-agent/daemon/internal/playbook"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
)

func (a *API) planInstruction(t planTarget) *sysagent.InstructionPreview {
	if playbook.AgentInstruction(t.rule) == "" {
		return nil
	}
	view := &sysagent.InstructionPreview{}
	if a.sysAgent == nil {
		view.Reason = "The system agent is unavailable."
		return view
	}
	if t.flag == nil || t.flag.Workspace == "" {
		view.Reason = "The finding has no recorded project folder."
		return view
	}
	p, err := a.sysAgent.PreviewInstruction(t.flag.Workspace, t.flag.Agent, t.rule)
	if err != nil {
		view.Reason = err.Error()
		return view
	}
	return &p
}

// Only the preview revision and subject cross the UI boundary. The destination
// and rule come from the current recorded finding, never from advisor prose.
func (a *API) handleAgentInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.sysAgentReady(w) {
		return
	}
	limitBody(w, r)
	var in struct {
		Subject  string `json:"subject"`
		Revision string `json:"revision"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.Subject == "" || len(in.Revision) != 64 {
		http.Error(w, "A subject and preview revision are required", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	t, found, err := a.resolvePlanTarget(in.Subject)
	if err != nil {
		http.Error(w, "Subject data unavailable; retry", http.StatusServiceUnavailable)
		return
	}
	if !found {
		http.Error(w, "Subject not found", http.StatusNotFound)
		return
	}
	if t.flag == nil || t.flag.Workspace == "" {
		http.Error(w, "No recorded project folder", http.StatusConflict)
		return
	}
	p, err := a.sysAgent.ApplyInstruction(t.flag.Workspace, t.flag.Agent, t.rule, in.Revision)
	if err != nil {
		writeSysAgentError(w, err)
		return
	}
	writeJSON(w, p)
}
