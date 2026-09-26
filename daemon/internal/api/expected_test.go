package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

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
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Key != "claude|gh|"+ghHosts+"|Cloudflare" {
		t.Fatalf("stored = %+v (%v)", p, err)
	}
	for id, acked := range map[string]bool{"same1": true, "same2": true, "other-dest": false} {
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
	if len(ex.Actions) == 0 || ex.Actions[0].ID != "expect" || ex.Actions[0].Label != "Expected: tool → GitHub" || ex.Actions[0].Path != "/expected" {
		t.Fatalf("actions = %+v, want expect first", ex.Actions)
	}
	if _, err := a.expected.Add(correlate.ExpectedPattern{Agent: "claude", Reader: "tool", Path: ghHosts, Dest: "GitHub"}); err != nil {
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
