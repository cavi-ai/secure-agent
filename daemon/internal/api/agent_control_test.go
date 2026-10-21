package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/localmodel"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
)

func TestAgentControlsAndForgetMemory(t *testing.T) {
	st := testStore(t)
	agent := sysagent.New(st, t.TempDir(), nil)
	api := New(Deps{Store: st, Workspace: WorkspaceDeps{SysAgent: agent}})
	mux := api.buildMux()
	defer localmodel.Default.PauseBackground(false)
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"action":"pause"}`, 200}, {`{"action":"resume"}`, 200}, {`{"action":"stop"}`, 200},
		{`{"action":"run"}`, 400}, {`{"action":"pause","command":"true"}`, 400}, {`{"action":"pause"} {}`, 400},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", "/agent/control", strings.NewReader(tc.body)))
		if w.Code != tc.code {
			t.Fatalf("control status %d for %s", w.Code, tc.body)
		}
	}
	if err := agent.Remember("/project", "finding", "Recorded detector finding", []string{"flag:one"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/agent/memory", nil))
	if w.Code != 200 || len(agent.Memory("/project")) != 0 {
		t.Fatalf("forget failed: %d", w.Code)
	}
}
