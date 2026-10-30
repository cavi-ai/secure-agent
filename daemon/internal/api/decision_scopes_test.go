package api

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type scopePeerChecker struct{}

func (scopePeerChecker) PeerCred(net.Conn) (PeerCred, error) { return PeerCred{PID: 42}, nil }

func scopedGuardDeps(t *testing.T) (Deps, model.DecisionScope) {
	t.Helper()
	st := testStore(t)
	now := time.Now().UTC()
	if err := st.UpsertSession(model.Session{ID: "session", Harness: "codex", Workspace: "/work", RootPID: 42, RootStartedAt: now.Format(time.RFC3339Nano), StartedAt: now, LastSeenAt: now, Status: model.SessionActive}); err != nil {
		t.Fatal(err)
	}
	identity := model.DecisionScope{Agent: "codex", SessionID: "session", Workspace: "/work", ReaderExe: "/bin/codex", IdentityBasis: "peer-process-tree"}
	deps := Deps{Store: st, Peers: PeerDeps{Checker: scopePeerChecker{}}, Guard: GuardDeps{Broker: guard.NewBroker(2 * time.Second), Identity: func(pid int32, id string) (model.DecisionScope, bool) {
		return identity, pid == 42 && (id == "" || id == "session")
	}}}
	return deps, identity
}

func scopedGuardAPI(t *testing.T) (*API, model.DecisionScope) {
	deps, identity := scopedGuardDeps(t)
	return New(deps), identity
}

func enqueueScopeGuard(t *testing.T, a *API, session string) (guard.Pending, <-chan *httptest.ResponseRecorder) {
	t.Helper()
	return enqueueGuardBody(t, a, `{"agent":"codex","session_id":"`+session+`","tool":"Read","path":"/work/.env","rule_id":"env"}`)
}

func enqueueGuardBody(t *testing.T, a *API, body string) (guard.Pending, <-chan *httptest.ResponseRecorder) {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		a.handleGuardDecision(w, httptest.NewRequest("POST", "/guard/decision", strings.NewReader(body)))
		done <- w
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if p := a.guardBroker.Pending(); len(p) == 1 {
			return p[0], done
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("guard prompt missing")
	return guard.Pending{}, done
}

func resolveScopeGuard(a *API, p guard.Pending, kind string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.handleGuardResolve(w, httptest.NewRequest("POST", "/guard/resolve", strings.NewReader(`{"id":"`+p.ID+`","verdict":"allow","scope":"`+kind+`"}`)))
	return w
}

func TestGuardScopedResolveAndRevocation(t *testing.T) {
	a, g := scopedGuardAPI(t)
	p, done := enqueueScopeGuard(t, a, "")
	if p.SessionID != "session" || len(p.AvailableScopes) != 4 {
		t.Fatalf("attested choices: %+v", p)
	}
	if !strings.HasSuffix(p.ScopeText, "Revoke under Protection → Rules & permissions.") {
		t.Fatalf("scope text names a missing view: %q", p.ScopeText)
	}
	w := resolveScopeGuard(a, p, "session")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if hook := <-done; hook.Code != 200 || !strings.Contains(hook.Body.String(), `"scope":"session"`) {
		t.Fatal(hook.Body.String())
	}
	g.RuleID = "env"
	g.ResourcePath = "/work/.env"
	g.Operation = "guard:Read"
	if !a.store.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("successful decision delivered before grant was saved")
	}
	rows, err := a.store.ListDecisionScopes()
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	var resolved struct {
		Receipt GuardResolveReceipt `json:"receipt"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved.Receipt.ID != p.ID || resolved.Receipt.SessionID != "session" || len(resolved.Receipt.ScopeIDs) != 1 || resolved.Receipt.ScopeIDs[0] != rows[0].ID {
		t.Fatalf("receipt did not identify committed permission: %+v %+v", resolved, rows)
	}
	history := a.store.SessionOutcomes("session")
	if len(history.Guards) != 1 || history.Guards[0].ResolutionID != p.ID || len(history.Guards[0].ScopeIDs) != 1 || history.Guards[0].ScopeIDs[0] != rows[0].ID {
		t.Fatalf("history lost permission: %+v", history.Guards)
	}
	revoke := httptest.NewRecorder()
	a.handleDecisionScopes(revoke, httptest.NewRequest("DELETE", "/decision-scopes?id="+rows[0].ID, nil))
	if revoke.Code != 200 || a.store.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("revocation failed")
	}
	p, done = enqueueScopeGuard(t, a, "session")
	resolveScopeGuard(a, p, "once")
	<-done
}

// A send after untrusted input can be allowed for the session: the next send
// to the same sink is answered from the saved permission without a prompt,
// and a different sink still asks.
func TestGuardUntrustedEgressSessionPermission(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	egress := func(sink string) string {
		return `{"agent":"codex","tool":"Bash","path":"` + sink + `","rule_id":"untrusted-egress","detail":"This session read untrusted content: web page https://example.com. It now sends data out: ` + sink + `."}`
	}
	p, done := enqueueGuardBody(t, a, egress("git push origin"))
	if len(p.AvailableScopes) != 5 {
		t.Fatalf("egress prompt offers only %+v", p.AvailableScopes)
	}
	if w := resolveScopeGuard(a, p, "session"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if hook := <-done; !strings.Contains(hook.Body.String(), `"verdict":"allow"`) {
		t.Fatal(hook.Body.String())
	}
	again := httptest.NewRecorder()
	a.handleGuardDecision(again, httptest.NewRequest("POST", "/guard/decision", strings.NewReader(egress("git push origin"))))
	var d guard.Decision
	if err := json.Unmarshal(again.Body.Bytes(), &d); err != nil || d.Verdict != "allow" || d.Reason != "saved-permission" {
		t.Fatalf("second send to the same sink: %s", again.Body.String())
	}
	other, done := enqueueGuardBody(t, a, egress("gh pr create"))
	if other.Path != "gh pr create" {
		t.Fatalf("other sink: %+v", other)
	}
	resolveScopeGuard(a, other, "once")
	<-done
}

// egressBody is a hook's untrusted-egress query naming its kinds of send.
func egressBody(sink string, categories ...string) string {
	c, _ := json.Marshal(categories)
	return `{"agent":"codex","tool":"Bash","path":"` + sink + `","rule_id":"untrusted-egress","categories":` + string(c) + `}`
}

// askGuard runs one hook query to completion. A request that prompts is
// answered by the broker's deadline (deny, "timeout").
func askGuard(t *testing.T, a *API, body string) guard.Decision {
	t.Helper()
	w := httptest.NewRecorder()
	a.handleGuardDecision(w, httptest.NewRequest("POST", "/guard/decision", strings.NewReader(body)))
	var d guard.Decision
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return d
}

func resolveGuardBody(a *API, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.handleGuardResolve(w, httptest.NewRequest("POST", "/guard/resolve", strings.NewReader(body)))
	return w
}

// Allowing a kind of send for the session covers its variants: other
// remotes and the default remote. Other kinds, and a command that adds an
// ungranted kind, still ask; the permission names the kind, the observed
// executable and workspace, and covers no other executable or workspace.
func TestGuardCategoryPermissionCoversVariants(t *testing.T) {
	a, identity := scopedGuardAPI(t)
	p, done := enqueueGuardBody(t, a, egressBody("git push origin", "git-push"))
	if offered, _ := json.Marshal(servedPending(t, a)["available_scopes"]); !strings.Contains(string(offered), `{"category":true,"kind":"session"}`) {
		t.Fatalf("no session permission for the kind of send: %s", offered)
	}
	w := resolveGuardBody(a, `{"id":"`+p.ID+`","verdict":"allow","scope":"session","category":true}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if hook := <-done; !strings.Contains(hook.Body.String(), `"verdict":"allow"`) {
		t.Fatal(hook.Body.String())
	}
	for _, sink := range []string{"git push upstream", "git push", "git push url"} {
		if d := askGuard(t, a, egressBody(sink, "git-push")); d.Verdict != "allow" || d.Reason != "saved-permission" {
			t.Fatalf("%s after a git-push session permission: %+v", sink, d)
		}
	}
	for _, body := range []string{egressBody("gh pr create", "gh-write"), egressBody("git push origin, gh pr create", "git-push", "gh-write")} {
		other, done := enqueueGuardBody(t, a, body)
		resolveScopeGuard(a, other, "once")
		<-done
	}
	rows, err := a.store.ListDecisionScopes()
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	var saved map[string]any
	raw, _ := json.Marshal(rows[0])
	_ = json.Unmarshal(raw, &saved)
	if saved["category"] != "git-push" || saved["resource_path"] != "" || saved["kind"] != "session" || saved["reader_exe"] != identity.ReaderExe || saved["workspace"] != identity.Workspace {
		t.Fatalf("saved permission: %s", raw)
	}
	covered := map[string]any{"agent": identity.Agent, "session_id": identity.SessionID, "workspace": identity.Workspace, "reader_exe": identity.ReaderExe,
		"identity_basis": identity.IdentityBasis, "rule_id": model.EgressRule, "operation": "guard:Bash", "category": "git-push", "resource_path": ""}
	if !a.store.MatchDecisionScopes([]model.DecisionScope{scopeFrom(t, covered, nil)}) {
		t.Fatal("permission does not cover its own kind")
	}
	for name, change := range map[string]map[string]any{
		"executable": {"reader_exe": "/bin/other"},
		"workspace":  {"workspace": "/other"},
		"kind":       {"category": "network-send"},
		"tool":       {"operation": "guard:WebFetch"},
	} {
		if a.store.MatchDecisionScopes([]model.DecisionScope{scopeFrom(t, covered, change)}) {
			t.Fatalf("permission covers another %s", name)
		}
	}
}

// scopeFrom decodes a permission request from its wire fields.
func scopeFrom(t *testing.T, fields, change map[string]any) model.DecisionScope {
	t.Helper()
	merged := map[string]any{}
	for k, v := range fields {
		merged[k] = v
	}
	for k, v := range change {
		merged[k] = v
	}
	raw, _ := json.Marshal(merged)
	var q model.DecisionScope
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	return q
}

// servedPending is the one pending request as /guard/pending serves it.
func servedPending(t *testing.T, a *API) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	a.handleGuardPending(w, httptest.NewRequest("GET", "/guard/pending", nil))
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatal(w.Body.String(), err)
	}
	return rows[0]
}

// A second prompt for the same kind of send in a session says so and
// preselects the session permission for that kind; another kind does not.
func TestGuardRepeatedKindPreselectsSessionPermission(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	ask := func(body string) map[string]any {
		p, done := enqueueGuardBody(t, a, strings.Replace(body, `{"agent"`, `{"session_id":"session","agent"`, 1))
		served := servedPending(t, a)
		resolveScopeGuard(a, p, "once")
		<-done
		return served
	}
	first := ask(egressBody("curl careers.example", "network-send"))
	if first["default_scope"] != nil || first["repeats"] != nil {
		t.Fatalf("first prompt of its kind: %v", first)
	}
	second := ask(egressBody("curl jobs.example", "network-send"))
	want := map[string]any{"kind": "session", "category": true}
	if got, _ := second["default_scope"].(map[string]any); second["repeats"] != float64(1) || !reflect.DeepEqual(got, want) {
		t.Fatalf("second prompt of its kind: %v", second)
	}
	if other := ask(egressBody("gh pr create", "gh-write")); other["default_scope"] != nil {
		t.Fatalf("another kind: %v", other)
	}
}

// A kind set to ask once per session preselects that session permission on
// its first prompt.
func TestGuardSessionCategoryModePreselects(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	p, done := enqueueGuardBody(t, a, `{"agent":"codex","tool":"Bash","path":"gh pr create","rule_id":"untrusted-egress","categories":["gh-write"],"category_mode":"session"}`)
	got, _ := servedPending(t, a)["default_scope"].(map[string]any)
	resolveScopeGuard(a, p, "once")
	<-done
	if !reflect.DeepEqual(got, map[string]any{"kind": "session", "category": true}) {
		t.Fatalf("default scope: %v", got)
	}
}

// Categories belong to untrusted-egress requests and name known kinds.
func TestGuardRejectsInvalidCategories(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	for _, body := range []string{
		`{"agent":"codex","tool":"Read","path":"/work/.env","rule_id":"env","categories":["git-push"]}`,
		egressBody("git push origin", "git-push", "git-push"),
		egressBody("rm -rf /", "anything"),
		`{"agent":"codex","tool":"Bash","path":"git push origin","rule_id":"untrusted-egress","categories":["git-push"],"category_mode":"always"}`,
	} {
		w := httptest.NewRecorder()
		a.handleGuardDecision(w, httptest.NewRequest("POST", "/guard/decision", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
}

// A category or standing answer the prompt did not offer saves nothing.
func TestGuardUnofferedPermissionSavesNothing(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	file, done := enqueueScopeGuard(t, a, "session")
	for _, body := range []string{
		`{"id":"` + file.ID + `","verdict":"allow","scope":"standing"}`,
		`{"id":"` + file.ID + `","verdict":"allow","scope":"session","category":true}`,
		`{"id":"` + file.ID + `","verdict":"allow","scope":"once","category":true}`,
	} {
		if w := resolveGuardBody(a, body); w.Code == 200 {
			t.Fatalf("%s accepted: %s", body, w.Body.String())
		}
	}
	resolveScopeGuard(a, file, "once")
	<-done
	if rows, err := a.store.ListDecisionScopes(); err != nil || len(rows) != 0 {
		t.Fatalf("unoffered answer saved %+v %v", rows, err)
	}
}

func TestGuardExistingSessionIsNotPermissionIdentity(t *testing.T) {
	deps, _ := scopedGuardDeps(t)
	deps.Guard.Identity = nil
	a := New(deps)
	p, done := enqueueScopeGuard(t, a, "session")
	if len(p.AvailableScopes) != 1 || p.AvailableScopes[0].Kind != "once" {
		t.Fatalf("client session gained reusable permission: %+v", p)
	}
	if w := resolveScopeGuard(a, p, "session"); w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
	rows, err := a.store.ListDecisionScopes()
	if err != nil || len(rows) != 0 {
		t.Fatal("unknown identity activated grant")
	}
	resolveScopeGuard(a, p, "once")
	<-done
}

func TestGuardScopeSaveFailureDoesNotAnswerAllow(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	p, done := enqueueScopeGuard(t, a, "session")
	a.store.Close()
	if w := resolveScopeGuard(a, p, "session"); w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
	select {
	case answer := <-done:
		t.Fatal("failed save answered request: " + answer.Body.String())
	default:
	}
	if len(a.guardBroker.Pending()) != 1 {
		t.Fatal("failed save withdrew prompt")
	}
	resolveScopeGuard(a, p, "once")
	<-done
}

func TestDecisionScopeListServesApplicability(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	p, done := enqueueScopeGuard(t, a, "")
	if w := resolveScopeGuard(a, p, "session"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	<-done
	rec := httptest.NewRecorder()
	a.handleDecisionScopes(rec, httptest.NewRequest("GET", "/decision-scopes", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var body []struct {
		Applicability model.ScopeApplicability `json:"applicability"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body[0].Applicability.Label != "Session permission" || !body[0].Applicability.Revoke {
		t.Fatalf("applicability: %s", rec.Body.String())
	}
	stored, err := a.store.ListDecisionScopes()
	if err != nil || len(stored) != 1 {
		t.Fatal(stored, err)
	}
	raw, err := json.Marshal(stored[0])
	if err != nil || strings.Contains(string(raw), "applicability") {
		t.Fatalf("stored scope includes applicability: %s %v", raw, err)
	}
}

func TestLegacyApprovalUnchanged(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	p, done := enqueueScopeGuard(t, a, "session")
	w := resolveScopeGuard(a, p, "always")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	<-done
	response := httptest.NewRecorder()
	a.handleGuardDecision(response, httptest.NewRequest("POST", "/guard/decision", strings.NewReader(`{"agent":"codex","tool":"Read","path":"/other/file","rule_id":"env"}`)))
	var d guard.Decision
	if err := json.Unmarshal(response.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "allow" || d.Reason != "cached" {
		t.Fatalf("legacy approval changed: %+v", d)
	}
}
