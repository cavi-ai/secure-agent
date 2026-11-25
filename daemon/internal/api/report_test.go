package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

var reportHeadings = []string{"## Summary", "## Models", "## Tools", "## Files touched", "## Network",
	"## Guard decisions", "## Findings", "## Secret hits", "## Timeline"}

// mdSection returns the body of one "## " section.
func mdSection(md, heading string) string {
	_, after, ok := strings.Cut(md, heading+"\n")
	if !ok {
		return ""
	}
	body, _, _ := strings.Cut(after, "\n## ")
	return strings.TrimSpace(body)
}

func TestSessionReportEndpoint(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	for _, sess := range []model.Session{
		{ID: "s1", Harness: "claude", Repo: "A", Branch: "main", StartedAt: now.Add(-10 * time.Minute), LastSeenAt: now},
		{ID: "s-empty", Harness: "codex", Workspace: "/w/scratch", StartedAt: now, LastSeenAt: now},
		{ID: "s-old", Harness: "claude", Repo: "A", Branch: "main", StartedAt: now.Add(-72 * time.Hour), LastSeenAt: now.Add(-71 * time.Hour)},
		{ID: "s-b", Harness: "claude", Repo: "B", StartedAt: now, LastSeenAt: now},
	} {
		sess.Status, sess.Confidence = model.SessionActive, model.ConfHook
		st.UpsertSession(sess)
	}
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now.Add(-9 * time.Minute), SessionID: "s1", ToolName: "Bash", ToolStatus: "ok", DurationMs: 1500, CallID: "c1"})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-8 * time.Minute), SessionID: "s1", Model: "m1", TokensIn: 100, TokensOut: 10, CostUSD: 0.25})
	mux := newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: func() Status { return Status{Running: true} }}).buildMux()
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	for _, path := range []string{"/sessions/s-empty/report", "/sessions/s-empty/report?format=json"} {
		rec := get(path)
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s: status %d type %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
		body := rec.Body.String()
		if strings.Contains(body, "null") {
			t.Fatalf("%s: body carries null: %s", path, body)
		}
		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"tools", "models", "files", "hosts", "guard", "secret_hits", "flags", "timeline"} {
			if arr, ok := raw[field].([]any); !ok || len(arr) != 0 {
				t.Errorf("%s: %s = %#v, want []", path, field, raw[field])
			}
		}
	}

	rec := get("/sessions/s1/report?format=md")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Fatalf("md: status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	md := rec.Body.String()
	if !strings.HasPrefix(md, "# claude · A@main — ") || !strings.Contains(md, "Session `s1` · active · identity: hook") {
		t.Fatalf("md head:\n%s", md)
	}
	for _, h := range reportHeadings {
		if !strings.Contains(md, "\n"+h+"\n") {
			t.Errorf("md missing %q", h)
		}
	}
	for _, h := range []string{"## Files touched", "## Network", "## Guard decisions", "## Findings", "## Secret hits"} {
		if got := mdSection(md, h); got != "none" {
			t.Errorf("%s = %q, want none", h, got)
		}
	}
	for _, want := range []string{"tool calls 1 (0 errors) · model calls 1 · tokens 100 in / 10 out · cost $0.25",
		"| m1 | 1 | 100 | 10 | $0.25 |", "| Bash | 1 | 0 | 1.5s |", " tool-call Bash ok 1.5s\n", " model-call m1\n"} {
		if !strings.Contains(md, want) {
			t.Errorf("md missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "null") {
		t.Fatalf("md carries null:\n%s", md)
	}
	empty := get("/sessions/s-empty/report?format=md").Body.String()
	if !strings.HasPrefix(empty, "# codex · /w/scratch — ") {
		t.Fatalf("empty md title: %q", strings.SplitN(empty, "\n", 2)[0])
	}
	for _, h := range reportHeadings[1:] {
		if got := mdSection(empty, h); got != "none" {
			t.Errorf("empty session %s = %q, want none", h, got)
		}
	}

	for path, want := range map[string]int{
		"/sessions/nope/report":             http.StatusNotFound,
		"/sessions/s1/other":                http.StatusNotFound,
		"/sessions/s1/report?format=xml":    http.StatusBadRequest,
		"/sessions?since=garbage":           http.StatusBadRequest,
		"/sessions?repo=A&since=not-a-date": http.StatusBadRequest,
	} {
		if rec := get(path); rec.Code != want {
			t.Errorf("%s: status %d, want %d", path, rec.Code, want)
		}
	}

	var list []model.Session
	rec = get("/sessions?repo=A&since=24h")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("/sessions?repo=A&since=24h: %d %v", rec.Code, err)
	}
	if len(list) != 1 || list[0].ID != "s1" {
		t.Fatalf("/sessions?repo=A&since=24h = %+v, want only s1", list)
	}
	rec = get("/sessions?harness=claude&branch=main")
	list = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("/sessions?harness=claude&branch=main = %+v, want s1 and s-old", list)
	}
}
