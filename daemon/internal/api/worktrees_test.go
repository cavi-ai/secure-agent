package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
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
	report := func() worktreehunter.ScanReport {
		t.Helper()
		rec := do(http.MethodGet, "/worktrees?refresh=1", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /worktrees: %d %s", rec.Code, rec.Body.String())
		}
		var rep worktreehunter.ScanReport
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

// worktreeFixture builds a repository with three linked worktrees, three
// days old (past the hunter's 24-hour grace): clean, dirty (an untracked
// file) and gone (directory deleted).
func worktreeFixture(t *testing.T) (home, root, repo, clean, dirty, gone string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home = t.TempDir()
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL": filepath.Join(home, "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
	} {
		t.Setenv(k, v)
	}
	root, _ = filepath.EvalSymlinks(t.TempDir())
	repo = filepath.Join(root, "repo")
	git := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	old := time.Now().Add(-72 * time.Hour)
	t.Setenv("GIT_COMMITTER_DATE", old.Format(time.RFC3339))
	git("init", "-q", "-b", "main", repo)
	git("-C", repo, "commit", "-q", "--allow-empty", "-m", "base")
	clean = filepath.Join(repo, ".worktrees", "clean")
	dirty = filepath.Join(repo, ".worktrees", "dirty")
	gone = filepath.Join(repo, ".worktrees", "gone")
	for _, p := range []string{clean, dirty, gone} {
		git("-C", repo, "worktree", "add", "-q", "-b", "feat/"+filepath.Base(p), p, "main")
		if err := os.Chtimes(filepath.Join(repo, ".git", "worktrees", filepath.Base(p), "index"), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dirty, "new.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}
	return home, root, repo, clean, dirty, gone
}

func TestWorktreeRemoveEndpoint(t *testing.T) {
	home, root, repo, clean, dirty, gone := worktreeFixture(t)

	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	mux := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: worktreehunter.New(st, home, worktreehunter.Options{})}).buildMux()
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/remove", strings.NewReader(body)))
		return rec
	}

	for _, c := range []struct {
		body string
		want int
	}{
		{`{}`, http.StatusBadRequest},
		{`{"path":"relative"}`, http.StatusBadRequest},
		{`{"prune":true,"repo":"relative"}`, http.StatusBadRequest},
		{`{"path":"` + repo + `"}`, http.StatusNotFound},
		{`{"path":"` + root + `"}`, http.StatusNotFound},
	} {
		if rec := post(c.body); rec.Code != c.want {
			t.Fatalf("POST %s: %d %s, want %d", c.body, rec.Code, rec.Body.String(), c.want)
		}
	}

	rec := post(`{"path":"` + dirty + `"}`)
	var refused struct {
		State   string   `json:"state"`
		Reasons []string `json:"reasons"`
	}
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &refused) != nil || refused.State != "keep" {
		t.Fatalf("dirty: %d %s, want 409 keep", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(dirty); err != nil {
		t.Fatal("refused removal deleted the worktree")
	}

	if rec := post(`{"path":"` + clean + `"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"removed"`) || !strings.Contains(rec.Body.String(), `"bytes":`) {
		t.Fatalf("clean: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(clean); err == nil {
		t.Fatal("clean worktree still on disk")
	}

	if rec := post(`{"prune":true,"repo":"` + repo + `"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), gone) {
		t.Fatalf("prune: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(`{"prune":true,"repo":"` + repo + `"}`); rec.Code != http.StatusConflict {
		t.Fatalf("second prune: %d, want 409", rec.Code)
	}

	actions := map[string]int{}
	for _, a := range st.RecentAudit(10) {
		actions[a.Action]++
	}
	if actions["worktree-remove"] != 1 || actions["worktree-prune"] != 1 {
		t.Fatalf("audit actions = %v", actions)
	}

	// The ledger books both actions; the report carries its totals.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cleanup/ledger?limit=10", nil))
	var ledger struct {
		Totals  model.CleanupTotals  `json:"totals"`
		Entries []model.CleanupEntry `json:"entries"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ledger) != nil ||
		len(ledger.Entries) != 2 || ledger.Entries[0].Action != "worktree-prune" || ledger.Entries[1].Path != clean ||
		ledger.Totals.Count != 2 || ledger.Totals.Bytes != ledger.Entries[1].Bytes {
		t.Fatalf("ledger: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/worktrees", nil))
	var rep worktreehunter.ScanReport
	if json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.Reclaimed == nil || rep.Reclaimed.Count != 2 {
		t.Fatalf("report reclaimed: %s", rec.Body.String())
	}
	for _, r := range apiroutes.Table {
		if strings.HasPrefix(r.Path, "/worktrees") || r.Path == "/cleanup/ledger" {
			if !r.NoAgent {
				t.Errorf("%s must be NoAgent: agents never read or change the machine's worktrees", r.Path)
			}
		}
	}
	if !apiroutes.IsMutation(http.MethodPost, "/worktrees/remove") || !apiroutes.ConsoleAllowed("/worktrees/remove") {
		t.Fatal("/worktrees/remove must be a console-admitted mutation")
	}
}

// The advisor's note is displayed only: a stored "remove" note on a keep
// row changes neither the verdict nor what Remove accepts.
func TestWorktreeAdviseAndNotes(t *testing.T) {
	home, _, repo, clean, dirty, gone := worktreeFixture(t)
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	var queued []model.WorktreeAdviceRequest
	hunter := worktreehunter.New(st, home, worktreehunter.Options{})
	mux := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: hunter,
		WorktreeAdvisor: func(r model.WorktreeAdviceRequest) bool { queued = append(queued, r); return true }}).buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	for _, c := range []struct {
		body string
		want int
	}{
		{`{"path":"relative"}`, http.StatusBadRequest},
		{`{"path":"` + repo + `"}`, http.StatusNotFound},
		{`{"path":"` + gone + `"}`, http.StatusConflict},
	} {
		if rec := do(http.MethodPost, "/worktrees/advise", c.body); rec.Code != c.want {
			t.Fatalf("advise %s: %d %s, want %d", c.body, rec.Code, rec.Body.String(), c.want)
		}
	}
	rec := do(http.MethodPost, "/worktrees/advise", `{"path":"`+dirty+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"queued":true`) {
		t.Fatalf("advise dirty: %d %s", rec.Code, rec.Body.String())
	}
	if len(queued) != 1 || queued[0].Path != dirty || queued[0].State != "keep" || queued[0].Head == "" {
		t.Fatalf("queued = %+v", queued)
	}

	// A note at the current HEAD shows; one at another HEAD does not.
	st.PutAdvisorVerdict(advisor.WorktreeSubjectID(dirty, queued[0].Head), "worktree",
		model.AdvisorVerdict{Assessment: "remove", Confidence: 1, Rationale: "looks disposable"})
	st.PutAdvisorVerdict(advisor.WorktreeSubjectID(clean, "0000000"), "worktree",
		model.AdvisorVerdict{Assessment: "keep", Rationale: "stale head"})
	if rec := do(http.MethodPost, "/worktrees/repos", `{"path":"`+repo+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("add repo: %d %s", rec.Code, rec.Body.String())
	}
	var rep worktreehunter.ScanReport
	if err := json.Unmarshal(do(http.MethodGet, "/worktrees?refresh=1", "").Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Advice) != 1 || rep.Advice[dirty].Assessment != "remove" {
		t.Fatalf("advice = %+v", rep.Advice)
	}
	for _, r := range rep.Repos {
		for _, w := range r.Worktrees {
			if w.Path == dirty && w.State != "keep" {
				t.Fatalf("a note changed the verdict: %+v", w)
			}
		}
	}
	if rec := do(http.MethodPost, "/worktrees/remove", `{"path":"`+dirty+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("remove after a remove note: %d %s, want 409", rec.Code, rec.Body.String())
	}
	if !apiroutes.IsMutation(http.MethodPost, "/worktrees/advise") || !apiroutes.ConsoleAllowed("/worktrees/advise") {
		t.Fatal("/worktrees/advise must be a console-admitted mutation")
	}

	unwired := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: hunter}).buildMux()
	rec = httptest.NewRecorder()
	unwired.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/advise", strings.NewReader(`{"path":"`+dirty+`"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("advise without an advisor: %d, want 503", rec.Code)
	}
}
