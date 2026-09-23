package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/playbook"
)

// PlanFuncs connect /advisor/plan to the current advisor. A nil PlanFuncs
// (or nil fields) reads as "advisor off".
type PlanFuncs struct {
	Enqueue func(advisor.PlanRequest) bool
	Pending func(subject string) bool
	Ready   func() (bool, string)
}

// PlanResponse is what /advisor/plan answers: the deterministic playbook
// always, the advisor's plan when one exists. Status is none, pending,
// ready, stale (the evidence changed since the plan) or disabled.
type PlanResponse struct {
	Subject      string             `json:"subject"`
	Status       string             `json:"status"`
	Playbook     playbook.Playbook  `json:"playbook"`
	Plan         *model.AdvisorPlan `json:"plan,omitempty"`
	AdvisorReady bool               `json:"advisor_ready"`
	Reason       string             `json:"reason,omitempty"`
}

// Plan context bounds.
const (
	planTimelineLines = 8
	planAccessLines   = 5
	planToolsTop      = 5
)

// planTarget is a resolved plan subject: a flag, an incident or an evidence
// file, with the finding, incident and file it involves.
type planTarget struct {
	subject   string
	kind      string // flag | incident | file
	flag      *model.Flag
	incident  *model.IncidentReport
	path      string
	findings  []model.FileFinding
	accesses  []model.FileAccess
	rule      string
	agent     string
	sessionID string
}

// resolvePlanTarget maps "flag:<id>", "incident:<id>" or "file:<path>" onto
// stored data; false when the subject names nothing stored.
func (a *API) resolvePlanTarget(subject string) (planTarget, bool) {
	kind, id, ok := strings.Cut(subject, ":")
	if !ok || id == "" {
		return planTarget{}, false
	}
	t := planTarget{subject: subject, kind: kind}
	switch kind {
	case "flag":
		f, ok := a.store.GetFlag(id)
		if !ok {
			return planTarget{}, false
		}
		t.flag = &f
		t.path = flagEvidencePath(f)
	case "incident":
		inc, err := a.store.GetIncident(id)
		if err != nil || inc == nil {
			return planTarget{}, false
		}
		t.incident = inc
		if f, ok := a.store.GetFlag(inc.FlagID); ok {
			t.flag = &f
		}
		if i := slices.IndexFunc(inc.TouchedFiles, func(p string) bool { return strings.HasPrefix(p, "/") }); i >= 0 {
			t.path = inc.TouchedFiles[i]
		}
	case "file":
		p, ok := evidencePath(id)
		if !ok {
			return planTarget{}, false
		}
		t.path = p
	default:
		return planTarget{}, false
	}
	if t.path != "" {
		t.findings = a.store.PathFindings(t.path, fileListLimit)
		t.accesses = a.store.PathAccesses(t.path, fileListLimit)
	}
	if kind == "file" {
		if len(t.findings) == 0 && len(t.accesses) == 0 {
			return planTarget{}, false
		}
		for _, f := range t.findings {
			if f.Kind == "flag" && t.flag == nil {
				if fl, ok := a.store.GetFlag(f.ID); ok {
					t.flag = &fl
				}
			}
			if f.Kind == "incident" && t.incident == nil {
				if inc, err := a.store.GetIncident(f.ID); err == nil && inc != nil {
					t.incident = inc
				}
			}
		}
	}
	switch {
	case t.flag != nil:
		t.rule, t.agent, t.sessionID = t.flag.Rule, t.flag.Agent, t.flag.SessionID
	case t.incident != nil:
		t.rule, t.agent, t.sessionID = t.incident.Rule, t.incident.Agent, t.incident.SessionID
	case len(t.accesses) > 0:
		t.sessionID = t.accesses[0].SessionID
	}
	return t, true
}

// flagEvidencePath is the first absolute path a flag's evidence names.
func flagEvidencePath(f model.Flag) string {
	for _, ev := range f.Evidence {
		if strings.HasPrefix(ev.Label, "/") {
			return ev.Label
		}
	}
	return ""
}

// planEvidenceKey fingerprints the evidence a plan is written from: the
// subject's flag and incident state and every finding naming its file. A
// new finding, an acknowledgement or a grown incident changes it.
func planEvidenceKey(t planTarget) string {
	parts := []string{t.subject}
	if t.flag != nil {
		parts = append(parts, fmt.Sprintf("flag:%s:%v", t.flag.ID, t.flag.Acknowledged))
	}
	if t.incident != nil {
		last := ""
		if t.incident.LastFlagAt != nil {
			last = t.incident.LastFlagAt.UTC().Format(time.RFC3339Nano)
		}
		parts = append(parts, fmt.Sprintf("incident:%s:%d:%s", t.incident.ID, t.incident.AggregateCount, last))
	}
	for _, f := range t.findings {
		parts = append(parts, fmt.Sprintf("%s:%s:%v:%s", f.Kind, f.ID, f.Acknowledged, f.Status))
	}
	slices.Sort(parts[1:])
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:8])
}

// planReady reports whether the advisor can take a plan, and why not.
func (a *API) planReady() (bool, string) {
	if a.plan == nil || a.plan.Ready == nil || a.plan.Enqueue == nil {
		return false, "the local advisor is off: enable it in Settings → Advisor"
	}
	return a.plan.Ready()
}

func (a *API) handleAdvisorPlan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.servePlan(w, r.URL.Query().Get("subject"))
	case http.MethodPost:
		var req struct {
			Subject string `json:"subject"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
			http.Error(w, "body must be {\"subject\": \"flag:<id>|incident:<id>|file:<path>\"}", http.StatusBadRequest)
			return
		}
		a.requestPlan(w, req.Subject)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) servePlan(w http.ResponseWriter, subject string) {
	t, ok := a.resolvePlanTarget(subject)
	if !ok {
		http.Error(w, "no stored flag, incident or evidence file matches this subject", http.StatusNotFound)
		return
	}
	resp := PlanResponse{Subject: subject, Status: "none", Playbook: playbook.For(t.rule)}
	resp.AdvisorReady, resp.Reason = a.planReady()
	if p, ok := a.store.AdvisorPlanFor(subject); ok {
		resp.Plan = &p
		resp.Status = "ready"
		if p.EvidenceKey != planEvidenceKey(t) {
			resp.Status = "stale"
		}
	}
	switch {
	case a.plan != nil && a.plan.Pending != nil && a.plan.Pending(subject):
		resp.Status = "pending"
	case resp.Plan == nil && !resp.AdvisorReady:
		resp.Status = "disabled"
	}
	writeJSON(w, resp)
}

func (a *API) requestPlan(w http.ResponseWriter, subject string) {
	t, ok := a.resolvePlanTarget(subject)
	if !ok {
		http.Error(w, "no stored flag, incident or evidence file matches this subject", http.StatusNotFound)
		return
	}
	resp := PlanResponse{Subject: subject, Playbook: playbook.For(t.rule)}
	resp.AdvisorReady, resp.Reason = a.planReady()
	if !resp.AdvisorReady {
		resp.Status = "disabled"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	req := advisor.PlanRequest{SubjectID: subject, EvidenceKey: planEvidenceKey(t),
		Context: a.planContext(t, resp.Playbook), Offered: a.offeredActions(t)}
	if !a.plan.Enqueue(req) {
		resp.Status, resp.AdvisorReady = "disabled", false
		resp.Reason = "the advisor did not take the request: it is paused or its queue is full"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	resp.Status = "pending"
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

// offeredActions are the served action ids the plan may recommend: the
// explained actions of the subject's flag.
func (a *API) offeredActions(t planTarget) []string {
	out := []string{}
	if t.flag == nil {
		return out
	}
	for _, act := range a.explainFlag(*t.flag, false).Actions {
		if !slices.Contains(out, act.ID) {
			out = append(out, act.ID)
		}
	}
	return out
}

// planContext renders the local context for one plan as labeled lines. It
// holds evidence labels, the session, the masked excerpt, history, local
// policy and the playbook; never a secret value.
func (a *API) planContext(t planTarget, pb playbook.Playbook) []string {
	var c []string
	add := func(format string, args ...any) { c = append(c, fmt.Sprintf(format, args...)) }

	add("subject: %s", t.subject)
	add("rule: %s (%s)", t.rule, pb.Title)
	if t.agent != "" {
		add("agent: %s", t.agent)
	}
	if f := t.flag; f != nil {
		ex := a.explainFlag(*f, false)
		add("finding: severity %d, raised %s, %s", f.Severity, f.TS.UTC().Format(time.RFC3339), ex.Disposition.Text)
		if ex.What != "" {
			add("what happened: %s", ex.What)
		}
		for _, line := range f.EvidenceStrings() {
			add("evidence: %s", line)
		}
		for _, eg := range ex.Egress {
			add("destination: %s port %d, %s %s, allowlisted %v", eg.Host, eg.Port, eg.Org, eg.Kind, eg.Allowlisted)
		}
		if cx := ex.Context; cx != nil && cx.Tool != "" {
			add("nearest tool call: %s (%s)", cx.Tool, cx.ToolStatus)
		}
		if cx := ex.Context; cx != nil && cx.Model != "" {
			add("model in use: %s", cx.Model)
		}
	}
	if inc := t.incident; inc != nil {
		add("incident: %s, risk %s, %d flags aggregated, %s", inc.ID, inc.Risk, max(inc.AggregateCount, 1), inc.Summary)
	}
	if t.sessionID != "" {
		a.planSessionLines(t, add)
	}
	if t.path != "" {
		d := a.fileDetail(t.path, t.findings, t.accesses)
		cat := ""
		if d.Subject != nil {
			cat = d.Subject.CategoryLabel + ", " + d.Subject.OwnerLabel
		}
		add("file: %s (%s), exists %v, %d bytes", t.path, cat, d.Exists, d.Size)
		for _, h := range d.Hits {
			add("file secret hit: rule %s", h.Rule)
		}
		if d.Excerpt != "" {
			add("file excerpt around the secret (secrets masked):\n%s", d.Excerpt)
		}
		for i, acc := range d.Accesses {
			if i == planAccessLines {
				break
			}
			add("agent file access: %s by %s at %s", acc.Kind, acc.ExePath, acc.TS)
		}
	}
	if t.rule != "" {
		d7, d30 := a.store.RuleCounts(t.rule, t.agent, time.Now())
		add("history: rule %s fired %d times for this agent in the last 7 days, %d in 30 days", t.rule, d7, d30)
	}
	if a.mutes != nil {
		if hosts := a.mutes.Load()[t.rule]; len(hosts) > 0 {
			add("local policy: flags of this rule are muted for %s", strings.Join(hosts, ", "))
		}
	}
	if a.allowlist != nil && t.agent != "" {
		if hosts := a.allowlist.Load()[t.agent]; len(hosts) > 0 {
			add("local policy: hosts allowed for %s: %s", t.agent, strings.Join(hosts, ", "))
		}
	}
	add("PLAYBOOK why: %s", pb.Why)
	for _, n := range pb.Now {
		add("PLAYBOOK now: %s", n)
	}
	for _, s := range pb.Prevent {
		add("PLAYBOOK prevent: (%s) %s: %s", s.Kind, s.Step, s.Detail)
	}
	return c
}

// planSessionLines adds the session summary and the timeline leading up to
// the finding.
func (a *API) planSessionLines(t planTarget, add func(string, ...any)) {
	rep, ok := a.store.SessionReport(t.sessionID)
	if !ok {
		return
	}
	s := rep.Session
	where := s.Workspace
	if s.Repo != "" {
		where = s.Repo
		if s.Branch != "" {
			where += "@" + s.Branch
		}
	}
	add("session: %s %s, %d min, %d turns, %d tool calls", s.Harness, where, rep.DurationS/60, rep.Turns, rep.ToolCalls)
	var tools []string
	for i, tc := range rep.Tools {
		if i == planToolsTop {
			break
		}
		tools = append(tools, fmt.Sprintf("%s×%d", tc.Key, tc.Count))
	}
	if len(tools) > 0 {
		add("session tools: %s", strings.Join(tools, ", "))
	}
	cutoff := ""
	if t.flag != nil {
		cutoff = t.flag.TS.UTC().Format(time.RFC3339Nano)
	}
	var lines []string
	for _, l := range rep.Timeline {
		if cutoff != "" && l.TS > cutoff {
			break
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s", l.TS, l.Kind, l.Label, l.Status))
	}
	if len(lines) > planTimelineLines {
		lines = lines[len(lines)-planTimelineLines:]
	}
	for _, l := range lines {
		add("session timeline: %s", strings.TrimSpace(l))
	}
}
