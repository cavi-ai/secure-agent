package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

func postJSON(h func(http.ResponseWriter, *http.Request), path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b))))
	return w
}

func TestLabelsRouteIsNoAgent(t *testing.T) {
	if !apiroutes.IsNoAgent("/labels") || !apiroutes.ConsoleAllowed("GET", "/labels") || !apiroutes.IsMutation("POST", "/labels") {
		t.Fatal("/labels must be NoAgent, console-admitted, POST mutating")
	}
}

// An explicit mark stores the flag's rule, agent and evidence path; bad
// labels, client-only sources and long reasons are refused.
func TestPostLabelMarksAFinding(t *testing.T) {
	a, _ := planTestAPI(t)
	p := seedTranscriptFinding(t, a)
	if w := postJSON(a.handleLabels, "/labels", map[string]string{"subject": "flag:f1", "label": "ok", "reason": "my own <test> key"}); w.Code != http.StatusOK {
		t.Fatalf("mark: %d %s", w.Code, w.Body.String())
	}
	got := a.store.SimilarLabels("secret-in-transcript", "codex", p, 5)
	if len(got) != 1 || got[0].Label != "ok" || got[0].Source != "mark" || got[0].Pattern != p || got[0].Reason != "my own <test> key" {
		t.Fatalf("stored = %+v", got)
	}
	if w := postJSON(a.handleLabels, "/labels", map[string]string{"subject": "flag:f1", "label": "not_ok", "source": "kill"}); w.Code != http.StatusOK {
		t.Fatalf("kill label: %d", w.Code)
	}
	for name, body := range map[string]map[string]string{
		"bad label":     {"subject": "flag:f1", "label": "maybe"},
		"server source": {"subject": "flag:f1", "label": "ok", "source": "allow-host"},
		"long reason":   {"subject": "flag:f1", "label": "ok", "reason": strings.Repeat("x", 201)},
	} {
		if w := postJSON(a.handleLabels, "/labels", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	if w := postJSON(a.handleLabels, "/labels", map[string]string{"subject": "flag:nope", "label": "ok"}); w.Code != http.StatusNotFound {
		t.Errorf("unknown subject: %d, want 404", w.Code)
	}
}

// Allowlisting, muting, path allows and guard answers record labels.
func TestDispositionsRecordLabels(t *testing.T) {
	a, _ := planTestAPI(t)
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, allowlistProcSource{})
	tg.Refresh()
	a.correlator = correlate.New(tg, sensitive.New(cfg), cfg)
	if w := postJSON(a.handleAllowlistAdd, "/allowlist", map[string]string{"agent": "codex", "host": "api.openai.com"}); w.Code != http.StatusOK {
		t.Fatalf("allowlist: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(a.handleMute, "/mute", map[string]string{"rule": "sensitive-read-then-connect", "host": "api.example.com"}); w.Code != http.StatusOK {
		t.Fatalf("mute: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(a.handleGuardPathAllow, "/guard/path-allow", map[string]string{"agent": "codex", "rule_id": "env-files", "path": "/w/api/.env"}); w.Code != http.StatusOK {
		t.Fatalf("path allow: %d %s", w.Code, w.Body.String())
	}
	done := make(chan guard.Decision, 1)
	go func() {
		done <- a.guardBroker.Request(guard.Pending{ID: "g1", Agent: "codex", Tool: "Read", Path: "/w/api/secrets.json", RuleID: "cloud-creds"})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(a.guardBroker.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if w := postJSON(a.handleGuardResolve, "/guard/resolve", map[string]string{"id": "g1", "verdict": "deny", "scope": "once"}); w.Code != http.StatusOK {
		t.Fatalf("resolve: %d", w.Code)
	}
	<-done
	postJSON(a.handleGuardResolve, "/guard/resolve", map[string]string{"id": "unknown", "verdict": "allow", "scope": "once"})

	check := func(rule, agent, pattern, label, source string) {
		t.Helper()
		for _, l := range a.store.SimilarLabels(rule, agent, pattern, 20) {
			if l.Rule == rule && l.Agent == agent && l.Pattern == pattern && l.Label == label && l.Source == source {
				return
			}
		}
		t.Errorf("no %s/%s label for %s %s %s", label, source, rule, agent, pattern)
	}
	check("", "codex", "api.openai.com", "ok", "allow-host")
	check("sensitive-read-then-connect", "", "api.example.com", "ok", "mute")
	check("env-files", "codex", "/w/api/.env", "ok", "allow-path")
	check("cloud-creds", "codex", "/w/api/secrets.json", "not_ok", "guard-deny")
	if n := len(a.store.SimilarLabels("", "", "unknown", 5)); n != 0 {
		t.Fatalf("unknown guard id wrote %d labels", n)
	}
}

// The flag explanation carries the operator's labels on the same case; the
// plan carries similar labels in its context and suggests the offered allow
// after three consistent ok labels, never on mixed labels.
func TestLabelsReachExplainPlanAndSuggestion(t *testing.T) {
	a, rec := planTestAPI(t)
	f := liveFixtureFlag()
	a.store.PutFlag(f)
	subject := "flag:" + f.ID
	for i := 0; i < 3; i++ {
		postJSON(a.handleLabels, "/labels", map[string]string{"subject": subject, "label": "ok", "reason": "routine config read"})
	}
	ex := a.explainFlag(f, false)
	if ex.Labels == nil || ex.Labels.OK != 3 || ex.Labels.NotOK != 0 {
		t.Fatalf("explain labels = %+v", ex.Labels)
	}
	_, resp := planCall(t, a, http.MethodGet, subject)
	if resp.Labels == nil || resp.Labels.Summary.OK != 3 || len(resp.Labels.Similar) != 3 || resp.Labels.Suggestion == nil || resp.Labels.Suggestion.Label != "ok" {
		t.Fatalf("plan labels = %+v", resp.Labels)
	}
	var offered []string
	for _, act := range ex.Actions {
		offered = append(offered, act.ID)
	}
	want := ""
	for _, id := range []string{"allow-path", "allow-host"} {
		if slices.Contains(offered, id) {
			want = id
			break
		}
	}
	if resp.Labels.Suggestion.ActionID != want {
		t.Fatalf("suggestion action = %q, want %q (offered %v)", resp.Labels.Suggestion.ActionID, want, offered)
	}
	planCall(t, a, http.MethodPost, subject)
	if all := strings.Join(rec.reqs[len(rec.reqs)-1].Context, "\n"); !strings.Contains(all, "operator label: ok (mark") || !strings.Contains(all, "routine config read") {
		t.Fatalf("plan context lacks operator labels:\n%s", all)
	}

	postJSON(a.handleLabels, "/labels", map[string]string{"subject": subject, "label": "not_ok"})
	if _, resp := planCall(t, a, http.MethodGet, subject); resp.Labels == nil || resp.Labels.Suggestion != nil {
		t.Fatalf("mixed labels must not suggest: %+v", resp.Labels)
	}
	_ = model.OperatorLabel{}
}
