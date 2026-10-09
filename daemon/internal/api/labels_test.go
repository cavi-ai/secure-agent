package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
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

func TestAdvisorPlanRejectsUnavailableLabelHistoryAndRecovers(t *testing.T) {
	for _, fault := range []string{"missing table", "invalid timestamp"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "history.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			st.PutFlag(model.Flag{ID: "f1", Rule: "secret-in-transcript", Agent: "codex", TS: time.Now(), Severity: 3})
			for i := 0; i < 3; i++ {
				if err := st.PutOperatorLabelResult(model.OperatorLabel{Kind: "flag", Rule: "secret-in-transcript", Agent: "codex", Label: "ok", Source: "mark"}); err != nil {
					t.Fatal(err)
				}
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			rec := &planRecorder{ready: true, pending: map[string]bool{}}
			a.plan = rec.funcs()
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			breakSQL, restoreSQL := `ALTER TABLE operator_labels RENAME TO saved_operator_labels`, `ALTER TABLE saved_operator_labels RENAME TO operator_labels`
			if fault == "invalid timestamp" {
				breakSQL = `UPDATE operator_labels SET created_at='invalid' WHERE id=1`
				restoreSQL = `UPDATE operator_labels SET created_at='2026-10-09T00:00:00Z' WHERE id=1`
			}
			if _, err := db.Exec(breakSQL); err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				code, _ := planCall(t, a, method, "flag:f1")
				if code != http.StatusServiceUnavailable {
					t.Errorf("%s plan with failed history: %d, want 503", method, code)
				}
			}
			if len(rec.reqs) != 0 {
				t.Errorf("enqueued %d plans with unavailable history", len(rec.reqs))
			}
			if health := st.WriteHealth(); len(health.ReadActive) == 0 {
				t.Error("unavailable operator history was absent from storage health")
			}
			if _, err := db.Exec(restoreSQL); err != nil {
				t.Fatal(err)
			}
			code, resp := planCall(t, a, http.MethodGet, "flag:f1")
			if code != http.StatusOK || resp.Labels == nil || resp.Labels.Summary.OK != 3 || len(resp.Labels.Similar) != 3 {
				t.Fatalf("recovered history: %d %+v", code, resp.Labels)
			}
			if code, _ := planCall(t, a, http.MethodPost, "flag:f1"); code != http.StatusAccepted {
				t.Fatalf("recovered plan request: %d", code)
			}
			if health := st.WriteHealth(); len(health.ReadActive) != 0 {
				t.Fatalf("recovered reads retained active faults: %+v", health)
			}
		})
	}
}

func TestExplicitLabelsReportFailedWriteAndAllowRetry(t *testing.T) {
	for _, subject := range []string{"flag:f1", "incident:i1"} {
		t.Run(subject, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "labels.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			st.PutFlag(model.Flag{ID: "f1", Rule: "secret-in-transcript", Agent: "codex", TS: time.Now()})
			if err := st.PutIncident(model.IncidentReport{ID: "i1", Rule: "secret-in-transcript", Agent: "codex", Timestamp: time.Now()}); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`CREATE TRIGGER reject_label_insert BEFORE INSERT ON operator_labels BEGIN SELECT RAISE(ABORT, 'fixture insert failure'); END`); err != nil {
				t.Fatal(err)
			}
			body := map[string]string{"subject": subject, "label": "ok"}
			w := postJSON(a.handleLabels, "/labels", body)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("failed label write returned %d: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "fixture insert failure") {
				t.Fatal("response exposed database diagnostics")
			}
			if health := st.WriteHealth(); !slices.Contains(health.Active, "operator labels") {
				t.Fatalf("failed label write hidden from health: %+v", health)
			}
			if got := st.LabelSummary("codex", "", "secret-in-transcript"); got.OK != 0 {
				t.Fatalf("failed judgment persisted: %+v", got)
			}
			if _, err := db.Exec(`DROP TRIGGER reject_label_insert`); err != nil {
				t.Fatal(err)
			}
			if w := postJSON(a.handleLabels, "/labels", body); w.Code != http.StatusOK {
				t.Fatalf("retry: %d %s", w.Code, w.Body.String())
			}
			if got := st.LabelSummary("codex", "", "secret-in-transcript"); got.OK != 1 {
				t.Fatalf("retry judgment: %+v", got)
			}
			if health := st.WriteHealth(); slices.Contains(health.Active, "operator labels") {
				t.Fatalf("successful retry left an active fault: %+v", health)
			}
		})
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
		done <- a.guardBroker.Request(context.Background(), guard.Pending{ID: "g1", Agent: "codex", Tool: "Read", Path: "/w/api/secrets.json", RuleID: "cloud-creds"})
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
