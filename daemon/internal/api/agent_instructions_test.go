package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
)

func TestAgentInstructionAppliesRecordedFindingOnly(t *testing.T) {
	st := testStore(t)
	agent := sysagent.New(st, t.TempDir(), nil)
	agent.SetConfig(config.SystemAgentConfig{Enabled: true, Endpoint: "http://127.0.0.1:11434"})
	a := New(Deps{Store: st, Workspace: WorkspaceDeps{SysAgent: agent}})
	dir := t.TempDir()
	if _, err := st.PutFlag(model.Flag{ID: "instruction-finding", Rule: "secret-in-transcript", Agent: "codex", Workspace: dir, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	code, plan := planCall(t, a, http.MethodGet, "flag:instruction-finding")
	if code != 200 || plan.Instruction == nil || !plan.Instruction.Ready {
		t.Fatalf("preview: %d %+v", code, plan.Instruction)
	}
	if plan.Instruction.Path != filepath.Join(dir, "AGENTS.md") {
		t.Fatal(plan.Instruction)
	}
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.handleAgentInstructions(w, httptest.NewRequest(http.MethodPost, "/agent/instructions", strings.NewReader(body)))
		return w
	}
	for _, body := range []string{
		`{"subject":"flag:instruction-finding","revision":"` + strings.Repeat("a", 64) + `"}`,
		`{"subject":"flag:missing","revision":"` + strings.Repeat("a", 64) + `"}`,
		`{"subject":"flag:instruction-finding","revision":"` + strings.Repeat("a", 64) + `","path":"/other/AGENTS.md","instruction":"untrusted"}`,
		`{"subject":"flag:instruction-finding","revision":"` + strings.Repeat("a", 64) + `"} {}`,
	} {
		if w := post(body); w.Code < 400 {
			t.Fatalf("unsafe request accepted: %d %s", w.Code, w.Body.String())
		}
		if _, err := os.Stat(plan.Instruction.Path); !os.IsNotExist(err) {
			t.Fatal("invalid request wrote a file")
		}
	}
	body, _ := json.Marshal(map[string]string{"subject": "flag:instruction-finding", "revision": plan.Instruction.Revision})
	w := post(string(body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	data, err := os.ReadFile(plan.Instruction.Path)
	if err != nil || !strings.Contains(string(data), plan.Instruction.Instruction) {
		t.Fatalf("file not updated: %q %v", data, err)
	}
	_, plan = planCall(t, a, http.MethodGet, "flag:instruction-finding")
	if plan.Instruction == nil || !plan.Instruction.Applied {
		t.Fatal("applied state unavailable")
	}
	if !apiroutes.IsMutation("POST", "/agent/instructions") || !apiroutes.IsNoAgent("/agent/instructions") {
		t.Fatal("instruction mutation must be pinned-UI only")
	}
	agent.SetConfig(config.SystemAgentConfig{Endpoint: "http://127.0.0.1:11434"})
	if w := post(string(body)); w.Code < 400 {
		t.Fatal("disabled agent wrote instructions")
	}
}
