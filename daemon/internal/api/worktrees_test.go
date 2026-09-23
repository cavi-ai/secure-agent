package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

func TestWorktreesEndpoints(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	repo, _ := filepath.EvalSymlinks(t.TempDir())
	repo = filepath.Join(repo, "repo")
	if out, err := exec.Command("git", "init", "-q", "-b", "main", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}

	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: worktreehunter.New(st, home, worktreehunter.Options{})})
	mux := a.buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	report := func() worktreehunter.Report {
		t.Helper()
		rec := do(http.MethodGet, "/worktrees?refresh=1", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /worktrees: %d %s", rec.Code, rec.Body.String())
		}
		var rep worktreehunter.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}

	if rep := report(); rep.Summary.Repos != 0 {
		t.Fatalf("empty machine reported repos: %+v", rep.Summary)
	}
	steps := []struct {
		body string
		want int
	}{
		{`{"path":"relative"}`, http.StatusBadRequest},
		{`{"path":"` + filepath.Dir(repo) + `"}`, http.StatusNotFound},
		{`{}`, http.StatusBadRequest},
		{`{"path":"` + repo + `","hidden":true}`, http.StatusNotFound},
		{`{"path":"` + repo + `/sub/dir"}`, http.StatusOK},
	}
	for _, s := range steps {
		if rec := do(http.MethodPost, "/worktrees/repos", s.body); rec.Code != s.want {
			t.Fatalf("POST %s: %d %s, want %d", s.body, rec.Code, rec.Body.String(), s.want)
		}
	}
	if rep := report(); rep.Summary.Repos != 1 || rep.Repos[0].Path != repo || rep.Repos[0].Source != "manual" {
		t.Fatalf("after add: %+v", rep.Repos)
	}
	if rec := do(http.MethodPost, "/worktrees/repos", `{"path":"`+repo+`","hidden":true}`); rec.Code != http.StatusOK {
		t.Fatalf("hide: %d %s", rec.Code, rec.Body.String())
	}
	if rep := report(); rep.Summary.Repos != 0 {
		t.Fatalf("hidden repo still reported: %+v", rep.Repos)
	}
	if rec := do(http.MethodPost, "/worktrees", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /worktrees: %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/worktrees/repos", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /worktrees/repos: %d", rec.Code)
	}

	if !apiroutes.ConsoleAllowed("/worktrees") || !apiroutes.ConsoleAllowed("/worktrees/repos") {
		t.Fatal("worktree routes not console-admitted")
	}
	if !apiroutes.IsMutation(http.MethodPost, "/worktrees/repos") || apiroutes.IsMutation(http.MethodGet, "/worktrees") {
		t.Fatal("worktree mutation classification wrong")
	}
}

func TestWorktreesUnwired(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	mux := newTestAPI("", st, nil, func() Status { return Status{Running: true} }).buildMux()
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/worktrees", nil),
		httptest.NewRequest(http.MethodPost, "/worktrees/repos", strings.NewReader(`{"path":"/x"}`)),
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s unwired: %d", req.Method, req.URL.Path, rec.Code)
		}
	}
}
