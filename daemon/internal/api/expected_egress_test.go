package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestExpectedEgressAPIRequiresEpisodeAndAudits(t *testing.T) {
	st := testStore(t)
	scope := store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
	if err := st.RecordEgressObservation(store.EgressObservation{Scope: scope, SessionID: "s1", Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordEgressObservation(store.EgressObservation{Scope: store.EgressScope{Agent: "claude"}, SessionID: "s2", Host: "203.0.113.9", Protocol: "tcp", Port: 443, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	var id, incompleteID string
	for _, episode := range st.ListEgressEpisodes(10) {
		if episode.ScopeComplete {
			id = episode.ID
		} else {
			incompleteID = episode.ID
		}
	}
	mux := newTestAPI("", st, nil, func() Status { return Status{Running: true} }).buildMux()
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/expected-egress", strings.NewReader(body)))
		return w
	}
	for _, body := range []string{`{"episode_id":"missing","kind":"scope"}`, `{"episode_id":"` + id + `","kind":"invalid"}`, `{"episode_id":"` + id + `","kind":"scope","workspace":"/other"}`} {
		if w := post(body); w.Code < 400 {
			t.Fatalf("accepted %s: %d", body, w.Code)
		}
	}
	if w := post(`{"episode_id":"` + incompleteID + `","kind":"scope"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("incomplete scope admitted: %d", w.Code)
	}
	w := post(`{"episode_id":"` + id + `","kind":"scope"}`)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var rule store.ExpectedEgressRule
	if err := json.Unmarshal(w.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.Kind != "scope" || rule.Workspace != "/work/a" || rule.Harness != "claude" || rule.ExePath != "/usr/bin/claude" {
		t.Fatalf("saved scope=%+v", rule)
	}
	if !st.ExpectedEgressMatch(store.EgressObservation{Scope: scope, Host: "203.0.113.2", Protocol: "tcp", Port: 443}) {
		t.Fatal("broad rule did not match changed destination")
	}
	get := httptest.NewRecorder()
	mux.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/expected-egress", nil))
	if get.Code != 200 || !bytes.Contains(get.Body.Bytes(), []byte(rule.ID)) {
		t.Fatalf("list: %d %s", get.Code, get.Body.String())
	}
	delete := httptest.NewRecorder()
	mux.ServeHTTP(delete, httptest.NewRequest(http.MethodDelete, "/expected-egress?id="+rule.ID, nil))
	if delete.Code != 200 {
		t.Fatalf("revoke: %d %s", delete.Code, delete.Body.String())
	}
	if st.ExpectedEgressMatch(store.EgressObservation{Scope: scope, Host: "203.0.113.2", Protocol: "tcp", Port: 443}) {
		t.Fatal("revoked rule still matches")
	}
	audit := st.RecentAudit(10)
	if len(audit) < 2 || audit[0].Action != "expected-egress-revoke" || audit[1].Action != "expected-egress-create" {
		t.Fatalf("audit=%+v", audit)
	}
}

func TestExpectedEgressConsoleRouteGate(t *testing.T) {
	for _, method := range []string{"GET", "POST", "DELETE"} {
		if !apiroutes.ConsoleAllowed(method, "/expected-egress") {
			t.Errorf("%s not console allowed", method)
		}
	}
	if apiroutes.ConsoleAllowed("PUT", "/expected-egress") {
		t.Fatal("unexpected method admitted")
	}
	if !apiroutes.IsNoAgent("/expected-egress") {
		t.Fatal("agent peers may create expected-egress rules")
	}
}
