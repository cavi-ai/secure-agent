package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func coverageProbeFixture(t *testing.T) (*API, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude", "hooks")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true, Agents: []AgentSummary{{PID: 40, Name: "claude"}}} }), dir
}

func probePost(a *API, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
	return w
}

func TestCoverageProbeRequiresHookRoundTripAndConfigurationContinuity(t *testing.T) {
	a, dir := coverageProbeFixture(t)
	w := probePost(a, "/coverage/probe", `{"harness":"claude"}`)
	if w.Code != 200 {
		t.Fatalf("start probe: %d %s", w.Code, w.Body.String())
	}
	var challenge struct{ ID, Path string }
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.ID == "" || challenge.Path == "" {
		t.Fatal("no inert challenge")
	}
	complete, _ := json.Marshal(map[string]any{"id": challenge.ID, "passed": true})
	if got := probePost(a, "/coverage/probe", string(complete)); got.Code != 409 {
		t.Fatalf("client invented a pass without daemon receipt: %d", got.Code)
	}
	query, _ := json.Marshal(map[string]any{"agent": "claude", "tool": "Read", "path": challenge.Path, "rule_id": "coverage-probe", "probe_id": challenge.ID})
	got := probePost(a, "/guard/decision", string(query))
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"verdict":"deny"`) {
		t.Fatalf("inert decision: %d %s", got.Code, got.Body.String())
	}
	if got := probePost(a, "/coverage/probe", string(complete)); got.Code != 200 || !strings.Contains(got.Body.String(), `"state":"passed"`) {
		t.Fatalf("complete: %d %s", got.Code, got.Body.String())
	}
	if got := probePost(a, "/coverage/probe", string(complete)); got.Code != 404 {
		t.Fatalf("replay extended proof: %d", got.Code)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret_guard.py"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	status := httptest.NewRecorder()
	a.buildMux().ServeHTTP(status, httptest.NewRequest("GET", "/status", nil))
	if !strings.Contains(status.Body.String(), `"state":"changed"`) {
		t.Fatalf("changed install retained pass: %s", status.Body.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "secret_guard.py"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	status = httptest.NewRecorder()
	a.buildMux().ServeHTTP(status, httptest.NewRequest("GET", "/status", nil))
	if !strings.Contains(status.Body.String(), `"state":"changed"`) {
		t.Fatal("restoring files resurrected an invalidated receipt")
	}
}

func TestCoverageProbeCannotAnswerRealAccess(t *testing.T) {
	a, _ := coverageProbeFixture(t)
	w := probePost(a, "/coverage/probe", `{"harness":"claude"}`)
	if w.Code != 200 {
		t.Fatalf("start: %d", w.Code)
	}
	var challenge struct{ ID string }
	json.Unmarshal(w.Body.Bytes(), &challenge)
	query, _ := json.Marshal(map[string]any{"agent": "claude", "tool": "Read", "path": "/real/project/.env", "rule_id": "coverage-probe", "probe_id": challenge.ID})
	if got := probePost(a, "/guard/decision", string(query)); got.Code != 409 {
		t.Fatalf("probe admitted real path: %d %s", got.Code, got.Body.String())
	}
	if got := probePost(a, "/coverage/probe", `{"harness":"codex"}`); got.Code != 400 {
		t.Fatalf("unsupported guard path got a probe: %d", got.Code)
	}
}
