package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestResolveSessionPrefixSeesRowsBeyondEndedListLimit(t *testing.T) {
	s := testStore(t)
	defer s.Close()
	a := New(Deps{Store: s})
	base := time.Now().UTC()
	if err := s.UpsertSession(model.Session{ID: "abcdef-old", Harness: "codex", StartedAt: base.Add(-24 * time.Hour), LastSeenAt: base.Add(-24 * time.Hour), Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(model.Session{ID: "abcdef-new", Harness: "claude", StartedAt: base, LastSeenAt: base, Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 499; i++ {
		id := fmt.Sprintf("recent-%04d", i)
		if err := s.UpsertSession(model.Session{ID: id, Harness: "codex", StartedAt: base, LastSeenAt: base.Add(time.Duration(i+1) * time.Second), Status: model.SessionEnded}); err != nil {
			t.Fatal(err)
		}
	}

	var recent []model.Session
	rec := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest("GET", "/sessions?status=ended&limit=500", nil))
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &recent) != nil {
		t.Fatalf("ended session list: %d %s", rec.Code, rec.Body.String())
	}
	if len(recent) != 500 {
		t.Fatalf("ended session list returned %d rows, want cap 500", len(recent))
	}
	newVisible := false
	for _, sess := range recent {
		if sess.ID == "abcdef-old" {
			t.Fatal("old matching session unexpectedly appeared in capped ended list")
		}
		newVisible = newVisible || sess.ID == "abcdef-new"
	}
	if !newVisible {
		t.Fatal("visible matching session is missing from capped ended list")
	}

	rec = httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest("GET", "/sessions/resolve?prefix=abcdef", nil))
	var matches []model.Session
	if rec.Code != 200 {
		t.Fatalf("prefix lookup returned %d, want 200 with both retained matches: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &matches); err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 || matches[0].ID != "abcdef-new" || matches[1].ID != "abcdef-old" {
		t.Fatalf("prefix matches = %+v, want two matches in ascending ID order", matches)
	}
}

func TestResolveSessionPrefixIsLiteralCappedAndSpansStatuses(t *testing.T) {
	s := testStore(t)
	defer s.Close()
	a := New(Deps{Store: s})
	now := time.Now().UTC()
	for _, sess := range []model.Session{
		{ID: "active-unique", Status: model.SessionActive},
		{ID: "idle-unique", Status: model.SessionIdle},
		{ID: "ended-unique", Status: model.SessionEnded},
		{ID: "wild%_*?[tail", Status: model.SessionActive},
		{ID: "MiXeD-Case", Status: model.SessionEnded},
		{ID: "multi-c", Status: model.SessionEnded},
		{ID: "éééééé-tail", Status: model.SessionEnded},
		{ID: "multi-a", Status: model.SessionActive},
		{ID: "multi-b", Status: model.SessionIdle},
	} {
		sess.Harness = "codex"
		sess.StartedAt, sess.LastSeenAt = now, now
		if err := s.UpsertSession(sess); err != nil {
			t.Fatal(err)
		}
	}
	for prefix, want := range map[string]string{
		"active-":   "active-unique",
		"idle-u":    "idle-unique",
		"ended-":    "ended-unique",
		"wild%_*?[": "wild%_*?[tail",
		"MiXeD-":    "MiXeD-Case",
		"éééééé":    "éééééé-tail",
	} {
		got := resolvePrefixForTest(t, a, prefix)
		if len(got) != 1 || got[0].ID != want {
			t.Errorf("prefix %q = %+v, want [%s]", prefix, got, want)
		}
	}
	if got := resolvePrefixForTest(t, a, "mixed-"); len(got) != 0 {
		t.Fatalf("case-folded prefix matched %+v", got)
	}
	if got := resolvePrefixForTest(t, a, "missing"); len(got) != 0 {
		t.Fatalf("no-match prefix returned %+v", got)
	}
	got := resolvePrefixForTest(t, a, "multi-")
	if len(got) != 2 || got[0].ID != "multi-a" || got[1].ID != "multi-b" {
		t.Fatalf("capped prefix matches = %+v, want first two IDs in binary ascending order", got)
	}
}

func TestResolveSessionPrefixValidationAndReadFailure(t *testing.T) {
	s := testStore(t)
	a := New(Deps{Store: s})
	for _, tc := range []struct {
		method, target string
		want           int
	}{
		{method: "GET", target: "/sessions/resolve", want: 400},
		{method: "GET", target: "/sessions/resolve?prefix=short", want: 400},
		{method: "GET", target: "/sessions/resolve?prefix=" + url.QueryEscape("ééé"), want: 400},
		{method: "GET", target: "/sessions/resolve?prefix=" + url.QueryEscape("\xffabcdef"), want: 400},
		{method: "POST", target: "/sessions/resolve?prefix=abcdef", want: 405},
	} {
		rec := httptest.NewRecorder()
		a.buildMux().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s returned %d, want %d", tc.method, tc.target, rec.Code, tc.want)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest("GET", "/sessions/resolve?prefix=abcdef", nil))
	if rec.Code != 503 {
		t.Fatalf("closed store returned %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

func resolvePrefixForTest(t *testing.T, a *API, prefix string) []model.Session {
	t.Helper()
	rec := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest("GET", "/sessions/resolve?prefix="+url.QueryEscape(prefix), nil))
	if rec.Code != 200 {
		t.Fatalf("prefix %q returned %d: %s", prefix, rec.Code, rec.Body.String())
	}
	var matches []model.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &matches); err != nil {
		t.Fatalf("prefix %q returned invalid JSON: %v", prefix, err)
	}
	return matches
}
