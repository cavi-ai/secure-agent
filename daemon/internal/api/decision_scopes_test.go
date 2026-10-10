package api

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type scopePeerChecker struct{}

func (scopePeerChecker) PeerCred(net.Conn) (PeerCred, error) { return PeerCred{PID: 42}, nil }

func scopedGuardAPI(t *testing.T) (*API, model.DecisionScope) {
	t.Helper()
	st := testStore(t)
	now := time.Now().UTC()
	if err := st.UpsertSession(model.Session{ID: "session", Harness: "codex", Workspace: "/work", RootPID: 42, RootStartedAt: now.Format(time.RFC3339Nano), StartedAt: now, LastSeenAt: now, Status: model.SessionActive}); err != nil {
		t.Fatal(err)
	}
	identity := model.DecisionScope{Agent: "codex", SessionID: "session", Workspace: "/work", ReaderExe: "/bin/codex", IdentityBasis: "peer-process-tree"}
	a := New(Deps{Store: st, Guard: guard.NewBroker(2 * time.Second), PeerChecker: scopePeerChecker{}, GuardIdentity: func(pid int32, id string) (model.DecisionScope, bool) {
		return identity, pid == 42 && (id == "" || id == "session")
	}})
	return a, identity
}

func enqueueScopeGuard(t *testing.T, a *API, session string) (guard.Pending, <-chan *httptest.ResponseRecorder) {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	body := `{"agent":"codex","session_id":"` + session + `","tool":"Read","path":"/work/.env","rule_id":"env"}`
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
	revoke := httptest.NewRecorder()
	a.handleDecisionScopes(revoke, httptest.NewRequest("DELETE", "/decision-scopes?id="+rows[0].ID, nil))
	if revoke.Code != 200 || a.store.MatchDecisionScopes([]model.DecisionScope{g}) {
		t.Fatal("revocation failed")
	}
	p, done = enqueueScopeGuard(t, a, "session")
	resolveScopeGuard(a, p, "once")
	<-done
}

func TestGuardExistingSessionIsNotPermissionIdentity(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	a.guardIdentity = nil
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
