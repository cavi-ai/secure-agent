package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type planRecorder struct {
	reqs    []advisor.PlanRequest
	pending map[string]bool
	ready   bool
}

func (p *planRecorder) funcs() *PlanFuncs {
	return &PlanFuncs{
		Enqueue: func(r advisor.PlanRequest) bool { p.reqs = append(p.reqs, r); return true },
		Pending: func(s string) bool { return p.pending[s] },
		Ready: func() (bool, string) {
			if p.ready {
				return true, ""
			}
			return false, "the local advisor is off"
		},
	}
}

func planTestAPI(t *testing.T) (*API, *planRecorder) {
	t.Helper()
	a := explainTestAPI(t)
	eng, err := firewall.NewEngine(config.FirewallConfig{Mode: "monitor"}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	eng.SetFingerprints([]config.Fingerprint{
		{ID: "fp1", Type: firewall.TypeEnvValue, Len: len(fileSecret), HMAC: firewall.Fingerprint([]byte("salt"), fileSecret)},
	})
	a.setFirewallForTest(FirewallControl{Engine: eng})
	rec := &planRecorder{pending: map[string]bool{}, ready: true}
	a.plan = rec.funcs()
	return a, rec
}

func planCall(t *testing.T, a *API, method, subject string) (int, PlanResponse) {
	t.Helper()
	w := httptest.NewRecorder()
	var r *http.Request
	if method == http.MethodGet {
		r = httptest.NewRequest(method, "/advisor/plan?subject="+url.QueryEscape(subject), nil)
	} else {
		body, _ := json.Marshal(map[string]string{"subject": subject})
		r = httptest.NewRequest(method, "/advisor/plan", strings.NewReader(string(body)))
	}
	a.handleAdvisorPlan(w, r)
	var resp PlanResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// seedTranscriptFinding writes a transcript with a registered secret, a flag
// and an incident naming it, and the codex session.
func seedTranscriptFinding(t *testing.T, a *API) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rollout-2026-09-23T12-53-26-s.jsonl")
	if err := os.WriteFile(p, []byte(`{"type":"session_meta"}`+"\n"+`{"output":"TOKEN=`+fileSecret+` ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a.store.UpsertSession(model.Session{ID: "s1", Harness: "codex", Workspace: "/w/api", Repo: "api", Branch: "main",
		StartedAt: now.Add(-time.Hour), LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfTranscript})
	a.store.PutFlag(model.Flag{ID: "f1", Rule: "secret-in-transcript", Severity: 3, TS: now, Agent: "codex", SessionID: "s1",
		Evidence: []model.EvidenceItem{{Kind: "transcript", Label: p, Sub: "fingerprint match", Rule: "fp1"}}})
	a.store.PutIncident(model.IncidentReport{ID: "inc-1", FlagID: "f1", Rule: "secret-in-transcript", Risk: "high", Agent: "codex",
		SessionID: "s1", Timestamp: now, TouchedFiles: []string{p}, Connections: []string{}, RotateList: []model.RotateItem{}})
	return p
}

func TestPlanRouteIsNoAgent(t *testing.T) {
	if !apiroutes.IsNoAgent("/advisor/plan") || !apiroutes.ConsoleAllowed("/advisor/plan") ||
		!apiroutes.IsMutation("POST", "/advisor/plan") || apiroutes.IsMutation("GET", "/advisor/plan") {
		t.Fatal("/advisor/plan must be NoAgent, console-admitted, POST mutating")
	}
}

// A subject is a stored flag, a stored incident or an evidence path.
func TestPlanSubjectResolution(t *testing.T) {
	a, _ := planTestAPI(t)
	p := seedTranscriptFinding(t, a)
	for _, s := range []string{"flag:f1", "incident:inc-1", "file:" + p} {
		code, resp := planCall(t, a, http.MethodGet, s)
		if code != http.StatusOK || resp.Playbook.Rule != "secret-in-transcript" || resp.Status != "none" {
			t.Errorf("%s: %d %+v", s, code, resp)
		}
	}
	for _, s := range []string{"flag:nope", "incident:nope", "file:/w/not-evidence", "file:relative", "bogus", ""} {
		if code, _ := planCall(t, a, http.MethodGet, s); code != http.StatusNotFound {
			t.Errorf("%q: %d, want 404", s, code)
		}
	}
}

// Without a ready advisor, asking is 409 with the reason and the playbook.
func TestPlanDisabledAdvisor(t *testing.T) {
	a, rec := planTestAPI(t)
	seedTranscriptFinding(t, a)
	rec.ready = false
	code, resp := planCall(t, a, http.MethodPost, "flag:f1")
	if code != http.StatusConflict || resp.Status != "disabled" || resp.Reason == "" || resp.Playbook.Why == "" || len(rec.reqs) != 0 {
		t.Fatalf("%d %+v reqs=%d", code, resp, len(rec.reqs))
	}
	a.plan = nil
	if code, resp := planCall(t, a, http.MethodGet, "flag:f1"); code != http.StatusOK || resp.Status != "disabled" || resp.AdvisorReady {
		t.Fatalf("unwired: %d %+v", code, resp)
	}
}

// The plan context carries the finding, session, masked excerpt, history
// and playbook, and never the secret.
func TestPlanContextIsLocalAndMasked(t *testing.T) {
	a, rec := planTestAPI(t)
	p := seedTranscriptFinding(t, a)
	code, resp := planCall(t, a, http.MethodPost, "incident:inc-1")
	if code != http.StatusAccepted || resp.Status != "pending" || len(rec.reqs) != 1 {
		t.Fatalf("%d %+v reqs=%d", code, resp, len(rec.reqs))
	}
	req := rec.reqs[0]
	all := strings.Join(req.Context, "\n")
	for _, want := range []string{"rule: secret-in-transcript", "agent: codex", "session: codex api@main", p,
		"[REDACTED:fp1]", "history:", "PLAYBOOK why:", "PLAYBOOK prevent:"} {
		if !strings.Contains(all, want) {
			t.Errorf("context lacks %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, fileSecret) {
		t.Fatal("the secret reached the plan context")
	}
	if req.SubjectID != "incident:inc-1" || req.EvidenceKey == "" || len(req.Offered) == 0 {
		t.Fatalf("request = %+v", req)
	}
}

// A stored plan is ready while the evidence is unchanged, stale after new
// evidence, and pending while the advisor is writing one.
func TestPlanStatusReadyStalePending(t *testing.T) {
	a, rec := planTestAPI(t)
	p := seedTranscriptFinding(t, a)
	subject := "file:" + p
	if code, _ := planCall(t, a, http.MethodPost, subject); code != http.StatusAccepted {
		t.Fatalf("post %d", code)
	}
	a.store.PutAdvisorPlan(subject, model.AdvisorPlan{Summary: "s", Why: []string{"w"}, Risk: "high",
		Prevent: []model.PlanStep{}, Behavior: []string{}, Remediate: []string{}, Actions: []string{},
		CreatedAt: time.Now(), EvidenceKey: rec.reqs[0].EvidenceKey})
	if _, resp := planCall(t, a, http.MethodGet, subject); resp.Status != "ready" || resp.Plan == nil || resp.Plan.Summary != "s" {
		t.Fatalf("ready: %+v", resp)
	}
	a.store.PutFlag(model.Flag{ID: "f2", Rule: "secret-in-transcript", Severity: 2, TS: time.Now(), Agent: "codex",
		Evidence: []model.EvidenceItem{{Kind: "transcript", Label: p, Rule: "aws-key"}}})
	if _, resp := planCall(t, a, http.MethodGet, subject); resp.Status != "stale" || resp.Plan == nil {
		t.Fatalf("stale: %+v", resp)
	}
	rec.pending[subject] = true
	if _, resp := planCall(t, a, http.MethodGet, subject); resp.Status != "pending" || resp.Plan == nil {
		t.Fatalf("pending: %+v", resp)
	}
}
