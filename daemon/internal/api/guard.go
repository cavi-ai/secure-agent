package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// guardTokenRE bounds "agent" and "rule_id" wherever a client supplies them:
// alphanumerics plus the separators these ids actually use. Both values flow
// into the store and are echoed back in JSON, so this closes off control
// characters, path-traversal segments, and shell metacharacters at the
// boundary rather than trusting every caller downstream.
var guardTokenRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type guardDecisionRequest struct {
	ProbeID   string `json:"probe_id,omitempty"`
	Agent     string `json:"agent"`
	SessionID string `json:"session_id,omitempty"`
	Tool      string `json:"tool"`
	Path      string `json:"path"`
	RuleID    string `json:"rule_id"`
	// Workspace is the hook's cwd, passed to the advisor so it can judge the
	// access in context. Optional (older hooks omit it).
	Workspace string `json:"workspace,omitempty"`
}

// handleGuardDecision answers a hook's prompt-mode query: a cached (agent,rule)
// decision is returned instantly; otherwise it enqueues a pending prompt and
// blocks until the menubar resolves it, the broker times out (deny), or the
// hook disconnects (prompt withdrawn, deny).
func (a *API) handleGuardDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req guardDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.RuleID == "" ||
		!guardTokenRE.MatchString(req.Agent) || !guardTokenRE.MatchString(req.RuleID) {
		http.Error(w, `Invalid payload: {"agent","tool","path","rule_id"} (agent/rule_id must match ^[A-Za-z0-9_.-]+$)`, http.StatusBadRequest)
		return
	}
	if req.ProbeID != "" {
		a.answerCoverageProbe(w, req)
		return
	}
	if a.guardBroker == nil {
		http.Error(w, "guard not enabled", http.StatusServiceUnavailable)
		return
	}
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&a.guardSeq, 1))
	var identity model.DecisionScope
	var peerPID int32
	if a.peerChk != nil && a.guardIdentity != nil {
		if cred, err := a.peerChk.PeerCred(connOf(r)); err == nil {
			if got, ok := a.guardIdentity(cred.PID, req.SessionID); ok && got.Agent == req.Agent {
				identity = got
				peerPID = cred.PID
				req.SessionID = identity.SessionID
			}
		}
	}
	// A supplied identity is only attributable if the durable session exists.
	// Never guess from the agent, workspace, or request time.
	if req.SessionID != "" {
		if _, ok := a.store.GetSession(req.SessionID); !ok {
			req.SessionID = ""
		}
	}
	record := func(d guard.Decision) {
		a.store.PutGuardDecision(store.GuardDecision{
			ID: id, SessionID: req.SessionID, RuleID: req.RuleID,
			Verdict: d.Verdict, Scope: d.Scope, At: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	identity.RuleID = req.RuleID
	identity.ResourcePath = req.Path
	identity.Operation = "guard:" + req.Tool
	if identity.IdentityBasis != "" && a.store.MatchDecisionScopes([]model.DecisionScope{identity}) {
		d := guard.Decision{Verdict: "allow", Scope: "scoped", Reason: "saved-permission"}
		record(d)
		writeJSON(w, d)
		return
	}
	// Per-path exceptions first: an operator-granted allow on THIS exact
	// path (or an ancestor of it) answers without prompting. Cheapest and
	// narrowest check first — one cached rule-wide allow must never widen
	// what a per-path allow does not cover.
	if a.store.GuardPathAllowed(req.Agent, req.RuleID, req.Path) {
		d := guard.Decision{Verdict: "allow", Scope: "always", Reason: "path-allow"}
		record(d)
		writeJSON(w, d)
		return
	}
	if g, ok := a.store.LookupGuardRule(req.Agent, req.RuleID); ok {
		d := guard.Decision{Verdict: g.Decision, Scope: "always", Reason: "cached"}
		record(d)
		writeJSON(w, d)
		return
	}
	// Offer the prompt to the advisor for a recommendation the operator sees
	// while deciding. Advisory only — the broker still blocks for the human.
	if a.guardAdvisor != nil {
		a.guardAdvisor(model.GuardAssessmentRequest{
			Agent: req.Agent, Tool: req.Tool, Path: req.Path, RuleID: req.RuleID,
			Workspace: req.Workspace,
		})
	}
	// Push, not just poll: SSE subscribers (menubar) refetch /guard/pending
	// immediately instead of waiting out their poll interval.
	a.publishGuardEvent(event.KindGuardPrompt, req.Agent+"/"+req.RuleID)
	scopes := []model.ScopeChoice{{Kind: "once"}}
	probe := identity
	model.ScopeChoice{Kind: "session"}.Apply(&probe, time.Now().UTC())
	if probe.Validate() == nil {
		scopes = append(scopes, model.ScopeChoice{Kind: "session"}, model.ScopeChoice{Kind: "exact", Expiry: "24h"}, model.ScopeChoice{Kind: "exact", Expiry: "7d"})
	}
	d := a.guardBroker.Request(r.Context(), guard.Pending{
		ID: id, SessionID: req.SessionID, Agent: req.Agent, Tool: req.Tool, Path: req.Path, RuleID: req.RuleID,
		Workspace: identity.Workspace, ReaderExe: identity.ReaderExe, IdentityBasis: identity.IdentityBasis, PeerPID: peerPID, AvailableScopes: scopes,
		// Disclose the blast radius of "allow always": the cached rule covers
		// every path this rule matches for this agent, not just this file.
		ScopeText: a.store.ExplainDecisionScope(identity) + " Once answers this request. Future permissions cover only this file, tool, workspace and observed executable path. Session permission ends with this session; timed permission expires after 24 hours or 7 days. Executable signatures are not verified. File approval does not authorize network access. Revoke in Policies.",
	})
	if r.Context().Err() != nil {
		// The hook stopped waiting (its own deadline, or the harness killed
		// it) and denied the call itself: an answer that lands now never
		// reached the agent, so it saves no rule and is recorded as a deny.
		d = guard.Decision{Verdict: "deny", Scope: "once", Reason: "withdrawn"}
	}
	if d.Scope == "always" && d.Reason == "" {
		a.store.PutGuardRule(store.GuardRule{Agent: req.Agent, RuleID: req.RuleID, Decision: d.Verdict, Source: "prompt"})
		a.store.PutAudit(store.AuditEntry{Action: "guard-rule", Rule: req.Agent + "/" + req.RuleID, ToMode: d.Verdict})
	}
	record(d)
	// Downstream fleet delivery: every resolved decision (cached, prompt, or
	// timeout-deny) is observable. Payload carries no secret material — paths
	// and rule ids only, mirroring what the console already shows.
	if a.fleetSinks != nil {
		a.fleetSinks.PublishGuardDecision(map[string]any{
			"agent": req.Agent, "tool": req.Tool, "path": req.Path,
			"rule_id": req.RuleID, "verdict": d.Verdict, "scope": d.Scope,
			"reason": d.Reason, "ts": time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, d)
}

func (a *API) handleGuardPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.guardBroker == nil {
		writeJSON(w, []guard.Pending{})
		return
	}
	pending := a.guardBroker.Pending()
	// Attach the advisor's recommendation, when one has landed. Advisory only:
	// the human still resolves; this just shows the model's read inline.
	for i := range pending {
		if v, ok := a.store.AdvisorVerdictFor(advisor.GuardSubjectID(pending[i].Agent, pending[i].RuleID, pending[i].Path, pending[i].Tool), "guard"); ok {
			pending[i].Advisor = &v
		}
	}
	// Broker.Pending() ranges a map, whose iteration order is unspecified —
	// sort oldest-first so the menubar always prompts the longest-waiting
	// request first instead of a random one.
	sort.Slice(pending, func(i, j int) bool { return pending[i].TS < pending[j].TS })
	writeJSON(w, pending)
}

type guardResolveRequest struct {
	ID      string `json:"id"`
	Verdict string `json:"verdict"` // allow | deny
	Scope   string `json:"scope"`   // once | always
	Expiry  string `json:"expiry,omitempty"`
}

func (a *API) handleGuardResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.guardBroker == nil {
		http.Error(w, "guard not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req guardResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" ||
		(req.Verdict != "allow" && req.Verdict != "deny") ||
		(req.Scope != "once" && req.Scope != "always" && req.Scope != "session" && req.Scope != "exact") ||
		(req.Scope == "exact" && (req.Expiry != "24h" && req.Expiry != "7d")) || (req.Scope != "exact" && req.Expiry != "") ||
		((req.Scope == "session" || req.Scope == "exact") && req.Verdict != "allow") {
		http.Error(w, `Invalid payload: {"id","verdict":"allow|deny","scope":"once|always"}`, http.StatusBadRequest)
		return
	}
	var pend *guard.Pending
	for _, p := range a.guardBroker.Pending() {
		if p.ID == req.ID {
			pend = &p
			break
		}
	}
	var prepare func(context.Context, guard.Pending) (func() error, func(), error)
	if req.Scope == "session" || req.Scope == "exact" {
		prepare = func(ctx context.Context, p guard.Pending) (func() error, func(), error) {
			if a.guardIdentity == nil || p.PeerPID <= 0 {
				return nil, nil, fmt.Errorf("identity unavailable; choose once")
			}
			g, valid := a.guardIdentity(p.PeerPID, p.SessionID)
			if !valid || g.Agent != p.Agent || g.Workspace != p.Workspace || g.ReaderExe != p.ReaderExe {
				return nil, nil, fmt.Errorf("identity changed; choose once")
			}
			g.ID = p.ID
			g.RuleID = p.RuleID
			g.ResourcePath = p.Path
			g.Operation = "guard:" + p.Tool
			model.ScopeChoice{Kind: req.Scope, Expiry: req.Expiry}.Apply(&g, time.Now().UTC())
			return a.store.PrepareDecisionScope(ctx, g)
		}
	}
	ok, err := a.guardBroker.ResolveWith(req.ID, guard.Decision{Verdict: req.Verdict, Scope: req.Scope}, prepare)
	if err != nil {
		http.Error(w, "Permission could not be saved. Refresh requests before trying again. "+err.Error(), 503)
		return
	}
	if ok {
		a.publishGuardEvent(event.KindGuardResolved, req.Verdict+"/"+req.Scope)
		if pend != nil {
			label := "ok"
			if req.Verdict == "deny" {
				label = "not_ok"
			}
			a.recordLabel(model.OperatorLabel{Kind: "guard", Rule: pend.RuleID, Agent: pend.Agent, Pattern: pend.Path,
				Label: label, Source: "guard-" + req.Verdict})
		}
	}
	writeJSON(w, map[string]any{"status": "ok", "resolved": ok})
}

// handleGuardPathAllow manages per-path guard exceptions: list (GET),
// add (POST {"agent","rule_id","path"}), revoke (DELETE ?agent=&rule_id=&path=).
// A path allow is narrower than a rule allow: it approves one file (and its
// descendants) instead of every path the rule matches. Mutations audited.
func (a *API) handleGuardPathAllow(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.store.ListGuardPathAllows(200))
	case http.MethodPost:
		if a.guardBroker == nil {
			http.Error(w, "guard not enabled", http.StatusServiceUnavailable)
			return
		}
		limitBody(w, r)
		var req struct {
			Agent  string `json:"agent"`
			RuleID string `json:"rule_id"`
			Path   string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.RuleID == "" || req.Path == "" ||
			!guardTokenRE.MatchString(req.Agent) || !guardTokenRE.MatchString(req.RuleID) {
			http.Error(w, `Invalid payload: {"agent","rule_id","path"} (agent/rule_id must match ^[A-Za-z0-9_.-]+$)`, http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(req.Path, "/") || len(req.Path) > 1024 || strings.Contains(req.Path, "\x00") {
			http.Error(w, "path must be an absolute filesystem path", http.StatusBadRequest)
			return
		}
		if err := a.store.PutGuardPathAllow(store.GuardPathAllow{Agent: req.Agent, RuleID: req.RuleID, Path: req.Path}); err != nil {
			http.Error(w, "could not save the file exception", http.StatusInternalServerError)
			return
		}
		a.recordLabel(model.OperatorLabel{Kind: "file", Rule: req.RuleID, Agent: req.Agent, Pattern: req.Path, Label: "ok", Source: "allow-path"})
		a.store.PutAudit(store.AuditEntry{
			Action: "guard-path-allow", Rule: req.Agent + "/" + req.RuleID,
			Detail: "allowed path " + req.Path,
		})
		a.publishGuardEvent(event.KindGuardResolved, "path-allow")
		writeJSON(w, map[string]any{"status": "ok", "agent": req.Agent, "rule_id": req.RuleID, "path": req.Path})
	case http.MethodDelete:
		agent := r.URL.Query().Get("agent")
		ruleID := r.URL.Query().Get("rule_id")
		path := r.URL.Query().Get("path")
		if agent == "" || ruleID == "" || path == "" ||
			!guardTokenRE.MatchString(agent) || !guardTokenRE.MatchString(ruleID) {
			http.Error(w, "agent, rule_id and path required", http.StatusBadRequest)
			return
		}
		removed := a.store.DeleteGuardPathAllow(agent, ruleID, path)
		if removed {
			a.store.PutAudit(store.AuditEntry{Action: "guard-path-allow-revoke", Rule: agent + "/" + ruleID, Detail: "revoked path " + path})
		}
		writeJSON(w, map[string]any{"status": "ok", "removed": removed})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGuardRules lists stored decisions (GET) and revokes one (DELETE ?agent=&rule_id=).
func (a *API) handleGuardRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.store.ListGuardRules(200))
	case http.MethodDelete:
		agent := r.URL.Query().Get("agent")
		ruleID := r.URL.Query().Get("rule_id")
		if agent == "" || ruleID == "" || !guardTokenRE.MatchString(agent) || !guardTokenRE.MatchString(ruleID) {
			http.Error(w, "agent and rule_id required, matching ^[A-Za-z0-9_.-]+$", http.StatusBadRequest)
			return
		}
		removed := a.store.DeleteGuardRule(agent, ruleID)
		if removed {
			a.store.PutAudit(store.AuditEntry{Action: "guard-rule-revoke", Rule: agent + "/" + ruleID})
		}
		writeJSON(w, map[string]any{"status": "ok", "removed": removed})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
