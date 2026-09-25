package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
)

func TestAgentRoutesAreNoAgentAndConsoleAdmitted(t *testing.T) {
	for _, p := range []string{"/agent/status", "/agent/skills", "/agent/chat", "/agent/plans", "/agent/dispatch", "/agent/runs"} {
		if !apiroutes.IsNoAgent(p) || !apiroutes.ConsoleAllowed("GET", p) {
			t.Errorf("%s: NoAgent=%v console=%v", p, apiroutes.IsNoAgent(p), apiroutes.ConsoleAllowed("GET", p))
		}
	}
	for _, p := range []string{"/agent/chat", "/agent/plans", "/agent/dispatch"} {
		if !apiroutes.IsMutation("POST", p) {
			t.Errorf("POST %s must be a pinned-UI mutation", p)
		}
	}
	for _, p := range []string{"/agent/chat", "/agent/plans"} {
		if !apiroutes.ConsoleAllowed("DELETE", p) || apiroutes.IsMutation("DELETE", p) {
			t.Errorf("DELETE %s: console-admitted, owner-level on the socket", p)
		}
	}
}

func TestAgentRoutesUnwired(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{} })
	for _, p := range []string{"/agent/status", "/agent/chat", "/agent/plans", "/agent/runs"} {
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s unwired: %d, want 503", p, w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/agent/skills", nil))
	var skills []sysagent.Skill
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &skills) != nil || len(skills) != 7 {
		t.Fatalf("skills: %d %s", w.Code, w.Body.String())
	}
}

func TestAgentChatPlansDispatch(t *testing.T) {
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			fmt.Fprint(w, `{"models":[{"name":"qwen3:latest"}]}`)
		case "/api/version":
			fmt.Fprint(w, `{"version":"0.15.0"}`)
		default:
			fmt.Fprint(w, `{"choices":[{"message":{"content":"Keys stay on this machine."}}]}`)
		}
	}))
	defer ollama.Close()
	st := testStore(t)
	agent := sysagent.New(st, t.TempDir(), func(s string) (string, bool) {
		return s, !strings.Contains(s, "UNMASKABLE")
	})
	// A harness model that is not pulled: no plan is ready, whatever is
	// installed on the machine running the test.
	agent.SetConfig(config.SystemAgentConfig{Enabled: true, Endpoint: ollama.URL, HarnessModel: "absent-model", TimeoutMinutes: 1})
	a := New(Deps{Store: st, SysAgent: agent})
	mux := a.buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}

	if w := do(http.MethodPost, "/agent/chat", `{"message":"where do my ssh keys live?","harness":"claude"}`); w.Code != http.StatusAccepted {
		t.Fatalf("send: %d %s", w.Code, w.Body.String())
	}
	agent.Wait()
	if w := do(http.MethodPost, "/agent/chat", `{"message":"UNMASKABLE"}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("secret: %d, want 422", w.Code)
	}
	var chat struct {
		Messages []model.SysAgentMessage
		Chatting bool
	}
	w := do(http.MethodGet, "/agent/chat", "")
	if json.Unmarshal(w.Body.Bytes(), &chat) != nil || chat.Chatting || len(chat.Messages) != 2 || chat.Messages[1].Content != "Keys stay on this machine." {
		t.Fatalf("chat: %s", w.Body.String())
	}

	w = do(http.MethodPost, "/agent/plans", `{"title":"Rotate","harness":"codex","mode":"terminal","workdir":"/tmp","task":"codex logout and login"}`)
	var saved struct{ Plan model.SysAgentPlan }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Plan.ID == 0 {
		t.Fatalf("save plan: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/agent/plans", `{"harness":"cursor","mode":"terminal","workdir":"/tmp","task":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown harness: %d", w.Code)
	}
	var plans []model.SysAgentPlan
	w = do(http.MethodGet, "/agent/plans", "")
	if json.Unmarshal(w.Body.Bytes(), &plans) != nil || len(plans) != 1 || plans[0].Ready {
		t.Fatalf("plans (the harness model is not pulled, so not ready): %s", w.Body.String())
	}
	if w := do(http.MethodPost, "/agent/dispatch", fmt.Sprintf(`{"plan_id":%d}`, saved.Plan.ID)); w.Code != http.StatusConflict {
		t.Fatalf("dispatch without the model: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/agent/dispatch", `{"plan_id":999}`); w.Code != http.StatusNotFound {
		t.Fatalf("dispatch unknown plan: %d", w.Code)
	}
	if w := do(http.MethodDelete, fmt.Sprintf("/agent/plans?id=%d", saved.Plan.ID), ""); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := do(http.MethodDelete, "/agent/chat", ""); w.Code != http.StatusOK || len(st.SysAgentMessages(10)) != 0 {
		t.Fatalf("clear: %d", w.Code)
	}
	var runs []model.SysAgentRun
	if w := do(http.MethodGet, "/agent/runs", ""); json.Unmarshal(w.Body.Bytes(), &runs) != nil || len(runs) != 0 {
		t.Fatalf("runs: %s", w.Body.String())
	}

	agent.SetConfig(config.SystemAgentConfig{Enabled: false, Endpoint: ollama.URL})
	if w := do(http.MethodPost, "/agent/chat", `{"message":"hi"}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "system_agent.enabled") {
		t.Fatalf("disabled: %d %s", w.Code, w.Body.String())
	}
	var status sysagent.AgentStatus
	if w := do(http.MethodGet, "/agent/status", ""); json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Enabled || len(status.Harnesses) != 4 {
		t.Fatalf("status: %s", w.Body.String())
	}
}
