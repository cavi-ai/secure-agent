package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestExpectedLoadFailureHasNoMutationSideEffects(t *testing.T) {
	for _, content := range []string{`[{"agent":"claude"},`, `null`} {
		for _, operation := range []string{"add", "add-all", "remove"} {
			t.Run(content+"/"+operation, func(t *testing.T) {
				a := expectedTestAPI(t)
				path := filepath.Join(t.TempDir(), "expected.json")
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				a.expected = correlate.NewExpectStore(path)
				f := ghFlag("fixture", time.Now(), ghRead("sensitive read", 900, "GitHub"), "evil.example.com")
				a.store.PutFlag(f)
				call(t, a, "GET", "/expected", "") // Exercise the cached load failure.
				method, endpoint, body := "POST", "/expected", `{"flag_id":"fixture"}`
				if operation == "add-all" {
					body = `{"flag_ids":["fixture"]}`
				}
				if operation == "remove" {
					method, body = "DELETE", ""
					endpoint += "?key=" + url.QueryEscape(correlate.ReadConnectKey("claude", "gh", ghHosts, "evil.example.com"))
				}
				w := call(t, a, method, endpoint, body)
				if w.Code != 500 {
					t.Fatalf("status = %d: %s", w.Code, w.Body)
				}
				if got, _ := a.store.GetFlag(f.ID); got.Acknowledged {
					t.Fatal("failed edit acknowledged the flag")
				}
				if labels := a.store.SimilarLabels(readConnectRule, "claude", ghHosts, 5); len(labels) != 0 {
					t.Fatalf("failed edit wrote labels: %+v", labels)
				}
				if audit := a.store.RecentAudit(10); len(audit) != 0 {
					t.Fatalf("failed edit wrote audit: %+v", audit)
				}
				if len(a.expected.List()) != 0 {
					t.Fatal("failed edit applied an exception")
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != content {
					t.Fatalf("policy changed: %q, %v", got, err)
				}
			})
		}
	}
}

func expectedTestAPI(t *testing.T) *API {
	t.Helper()
	pinExplainHome(t, "/Users/dev")
	a := explainTestAPI(t)
	a.expected = correlate.NewExpectStore(filepath.Join(t.TempDir(), "expected.json"))
	return a
}

func call(t *testing.T, a *API, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w
}

// Marking a flag expected stores its pattern, reviews the open flags of that
// pattern only, writes an ok label and an audit entry; Forget removes it.
func TestExpectedFlow(t *testing.T) {
	a := expectedTestAPI(t)
	now := time.Now()
	cf := ghRead("sensitive read", 900, "GitHub")
	a.store.PutFlag(ghFlag("same1", now, cf, "2606:4700::6812:105d"))
	a.store.PutFlag(ghFlag("same2", now.Add(time.Minute), cf, "2606:4700::6812:1111"))
	a.store.PutFlag(ghFlag("other-dest", now, cf, "evil.example.com"))
	a.store.PutFlag(ghFlag("legacy", now, ghRead("sensitive read", 0), "2606:4700::6812:105d"))
	a.store.PutFlag(ghFlag("legacy-noexe", now, model.EvidenceItem{Kind: "read", Label: ghHosts, Sub: "sensitive read"}, "2606:4700::6812:105d"))

	if w := call(t, a, "POST", "/expected", `{"flag_id":"legacy-noexe"}`); w.Code != 422 {
		t.Fatalf("flag without a reader: status %d, want 422", w.Code)
	}
	if w := call(t, a, "POST", "/expected", `{"flag_id":"nope"}`); w.Code != 404 {
		t.Fatalf("unknown flag: status %d, want 404", w.Code)
	}
	w := call(t, a, "POST", "/expected", `{"flag_id":"same1"}`)
	if w.Code != 200 {
		t.Fatalf("POST status %d: %s", w.Code, w.Body)
	}
	var p correlate.ExpectedPattern
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Key != "claude|gh|"+ghHosts+"|2606:4700::6812:105d" {
		t.Fatalf("stored = %+v (%v)", p, err)
	}
	for id, acked := range map[string]bool{"same1": true, "same2": false, "other-dest": false} {
		if f, _ := a.store.GetFlag(id); f.Acknowledged != acked {
			t.Errorf("%s acknowledged = %v, want %v", id, f.Acknowledged, acked)
		}
	}
	if labels := a.store.SimilarLabels(readConnectRule, "claude", ghHosts, 5); len(labels) != 1 || labels[0].Label != "ok" || labels[0].Source != "expect" {
		t.Fatalf("labels = %+v, want one ok/expect", labels)
	}
	if audit := a.store.RecentAudit(10); len(audit) == 0 || audit[0].Action != "expect-add" {
		t.Fatalf("audit = %+v, want expect-add first", audit)
	}
	var list []correlate.ExpectedPattern
	if err := json.Unmarshal(call(t, a, "GET", "/expected", "").Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("GET = %+v (%v)", list, err)
	}
	if w := call(t, a, "DELETE", "/expected?key="+p.Key, ""); w.Code != 200 {
		t.Fatalf("DELETE status %d", w.Code)
	}
	if w := call(t, a, "DELETE", "/expected?key="+p.Key, ""); w.Code != 404 {
		t.Fatalf("second DELETE status %d, want 404", w.Code)
	}
	if !apiroutes.IsNoAgent("/expected") || !apiroutes.IsMutation("POST", "/expected") || !apiroutes.ConsoleAllowed("DELETE", "/expected") {
		t.Fatal("/expected must be NoAgent, a POST mutation, and console-deletable")
	}
}

// The card offers Expected first while the pattern is not expected yet.
func TestExpectActionOffered(t *testing.T) {
	a := expectedTestAPI(t)
	f := ghFlag("x", time.Now(), ghRead("agent tool read", 900, "GitHub"), "140.82.114.6")
	a.store.PutFlag(f)
	ex := a.explainFlag(f, false)
	if len(ex.Actions) == 0 || ex.Actions[0].ID != "expect" || ex.Actions[0].Label != "Expected: tool → 140.82.114.6" || ex.Actions[0].Path != "/expected" {
		t.Fatalf("actions = %+v, want expect first", ex.Actions)
	}
	if _, err := a.expected.Add(correlate.ExpectedPattern{Agent: "claude", Reader: "tool", Path: ghHosts, Dest: "140.82.114.6"}); err != nil {
		t.Fatal(err)
	}
	for _, act := range a.explainFlag(f, false).Actions {
		if act.ID == "expect" {
			t.Fatal("expect offered for a pattern already expected")
		}
	}
	legacy := ghFlag("y", time.Now(), model.EvidenceItem{Kind: "read", Label: ghHosts}, "140.82.114.6")
	for _, act := range a.explainFlag(legacy, false).Actions {
		if act.ID == "expect" {
			t.Fatal("expect offered for a flag without a recorded reader")
		}
	}
}

func TestPatternOffersExpect(t *testing.T) {
	a := expectedTestAPI(t)
	start := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 3; i++ {
		a.store.PutFlag(ghFlag(string(rune('a'+i)), start.Add(time.Duration(i)*time.Minute), ghRead("sensitive read", 901, "GitHub"), "evil.example.com"))
	}
	p := onlyPattern(t, a.computePatterns(time.Now().Add(-24*time.Hour), 3))
	if len(p.Actions) == 0 || p.Actions[0].ID != "expect" || p.Actions[0].Body["flag_id"] != "c" {
		t.Fatalf("pattern actions = %+v, want expect for the newest open flag first", p.Actions)
	}
}

// Expected destinations are exact endpoints, not every tenant on a CDN.
func TestExpectedEndpointScopeAndMixedEvidence(t *testing.T) {
	a := expectedTestAPI(t)
	now := time.Now()
	f := ghFlag("selected", now, ghRead("sensitive read", 900, "GitHub"), "2606:4700::6812:105d")
	a.store.PutFlag(f)
	a.store.PutFlag(ghFlag("other-address", now, ghRead("sensitive read", 900, "GitHub"), "2606:4700::6812:1111"))
	mixed := f
	mixed.ID = "mixed"
	mixed.Evidence = append(append([]model.EvidenceItem(nil), f.Evidence...), model.EvidenceItem{Kind: "connect", Label: "evil.example.com:443", PID: 900})
	a.store.PutFlag(mixed)
	w := call(t, a, "POST", "/expected", `{"flag_id":"selected"}`)
	if w.Code != 200 {
		t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
	for id, want := range map[string]bool{"selected": true, "other-address": false, "mixed": false} {
		f, _ := a.store.GetFlag(id)
		if f.Acknowledged != want {
			t.Errorf("%s acknowledged=%v want %v", id, f.Acknowledged, want)
		}
	}
}

func TestNonSecretFileExceptionIsExactAndReversible(t *testing.T) {
	a := expectedTestAPI(t)
	now := time.Now()
	f := ghFlag("fixture", now, model.EvidenceItem{Kind: "read", Label: "/project/test/.env", Sub: "sensitive read", PID: 900, Exe: "/bin/cat"}, "api.example.com")
	a.store.PutFlag(f)
	mixed := f
	mixed.ID = "mixed-file"
	mixed.Evidence = append(append([]model.EvidenceItem(nil), f.Evidence...), model.EvidenceItem{Kind: "read", Label: "/project/prod/.env", PID: 900, Exe: "/bin/cat"})
	a.store.PutFlag(mixed)
	w := call(t, a, "POST", "/expected", `{"flag_id":"fixture","scope":"file"}`)
	if w.Code != 200 {
		t.Fatalf("POST %d %s", w.Code, w.Body)
	}
	var entry correlate.ExpectedPattern
	json.Unmarshal(w.Body.Bytes(), &entry)
	if !a.expected.Match([]string{"claude|node|/project/test/.env|other.example.com"}, now) {
		t.Fatal("marked non-secret fixture still flags")
	}
	if a.expected.Match([]string{"codex|node|/project/test/.env|other.example.com"}, now) {
		t.Fatal("exception escaped agent scope")
	}
	if a.expected.Match([]string{"claude|node|/project/test/.env.local|other.example.com"}, now) {
		t.Fatal("exception escaped exact file")
	}
	if f, _ := a.store.GetFlag("mixed-file"); f.Acknowledged {
		t.Fatal("mixed sensitive file was hidden")
	}
	if w := call(t, a, "DELETE", "/expected?key="+entry.Key, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if a.expected.Match([]string{"claude|node|/project/test/.env|other.example.com"}, now) {
		t.Fatal("revoked exception still matches")
	}
}

func TestMixedFindingOffersNextUncoveredPair(t *testing.T) {
	a := expectedTestAPI(t)
	f := ghFlag("mixed", time.Now(), ghRead("sensitive read", 900, "GitHub"), "one.example.com")
	f.Evidence = append(f.Evidence, model.EvidenceItem{Kind: "connect", Label: "two.example.com:443", PID: 900})
	a.store.PutFlag(f)
	w := call(t, a, "POST", "/expected", `{"flag_id":"mixed"}`)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	act, ok := a.expectAction(f)
	if !ok || act.Body["host"] != "two.example.com" {
		t.Fatalf("next action=%+v", act)
	}
	w = call(t, a, "POST", "/expected", `{"flag_id":"mixed","path":"/Users/dev/.config/gh/hosts.yml","host":"two.example.com"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if f, _ := a.store.GetFlag(f.ID); !f.Acknowledged {
		t.Fatal("fully covered finding should be reviewed")
	}
	if w := call(t, a, "POST", "/expected", `{"flag_id":"mixed","path":"/arbitrary/.env","host":"two.example.com"}`); w.Code != 422 {
		t.Fatal("injected path accepted", w.Code)
	}
}
