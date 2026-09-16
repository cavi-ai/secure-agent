package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// guardTokenRE bounds "agent" and "rule_id" wherever a client supplies them:
// alphanumerics plus the separators these ids actually use. Both values flow
// into the store and are echoed back in JSON, so this closes off control
// characters, path-traversal segments, and shell metacharacters at the
// boundary rather than trusting every caller downstream.
var guardTokenRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type guardDecisionRequest struct {
	Agent  string `json:"agent"`
	Tool   string `json:"tool"`
	Path   string `json:"path"`
	RuleID string `json:"rule_id"`
}

// handleGuardDecision answers a hook's prompt-mode query: a cached (agent,rule)
// decision is returned instantly; otherwise it enqueues a pending prompt and
// blocks until the menubar resolves it or the broker times out (deny).
func (a *API) handleGuardDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.guardBroker == nil {
		http.Error(w, "guard not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req guardDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.RuleID == "" ||
		!guardTokenRE.MatchString(req.Agent) || !guardTokenRE.MatchString(req.RuleID) {
		http.Error(w, `Invalid payload: {"agent","tool","path","rule_id"} (agent/rule_id must match ^[A-Za-z0-9_.-]+$)`, http.StatusBadRequest)
		return
	}
	// Per-path exceptions first: an operator-granted allow on THIS exact
	// path (or an ancestor of it) answers without prompting. Cheapest and
	// narrowest check first — one cached rule-wide allow must never widen
	// what a per-path allow does not cover.
	if a.store.GuardPathAllowed(req.Agent, req.RuleID, req.Path) {
		writeJSON(w, guard.Decision{Verdict: "allow", Scope: "always", Reason: "path-allow"})
		return
	}
	if g, ok := a.store.LookupGuardRule(req.Agent, req.RuleID); ok {
		writeJSON(w, guard.Decision{Verdict: g.Decision, Scope: "always", Reason: "cached"})
		return
	}
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&a.guardSeq, 1))
	// Push, not just poll: SSE subscribers (menubar) refetch /guard/pending
	// immediately instead of waiting out their poll interval.
	a.publishGuardEvent(event.KindGuardPrompt, req.Agent+"/"+req.RuleID)
	d := a.guardBroker.Request(guard.Pending{
		ID: id, Agent: req.Agent, Tool: req.Tool, Path: req.Path, RuleID: req.RuleID,
		// Disclose the blast radius of "allow always": the cached rule covers
		// every path this rule matches for this agent, not just this file.
		ScopeText: "Allow Always approves every path under rule \"" + req.RuleID + "\" for agent \"" + req.Agent + "\", not just this one.",
	})
	if d.Scope == "always" && d.Reason == "" {
		a.store.PutGuardRule(store.GuardRule{Agent: req.Agent, RuleID: req.RuleID, Decision: d.Verdict, Source: "prompt"})
		a.store.PutAudit(store.AuditEntry{Action: "guard-rule", Rule: req.Agent + "/" + req.RuleID, ToMode: d.Verdict})
	}
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
		(req.Scope != "once" && req.Scope != "always") {
		http.Error(w, `Invalid payload: {"id","verdict":"allow|deny","scope":"once|always"}`, http.StatusBadRequest)
		return
	}
	ok := a.guardBroker.Resolve(req.ID, guard.Decision{Verdict: req.Verdict, Scope: req.Scope})
	if ok {
		a.publishGuardEvent(event.KindGuardResolved, req.Verdict+"/"+req.Scope)
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
		a.store.PutGuardPathAllow(store.GuardPathAllow{Agent: req.Agent, RuleID: req.RuleID, Path: req.Path})
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
