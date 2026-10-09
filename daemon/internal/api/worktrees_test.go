package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentask"
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

	if !apiroutes.ConsoleAllowed("GET", "/worktrees") || !apiroutes.ConsoleAllowed("GET", "/worktrees/repos") {
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

// With "async": true the removal answers 202 at once; GET /worktrees
// reports its outcome under removals and drops the row.
func TestWorktreeRemoveAsync(t *testing.T) {
	home, _, _, clean, dirty, _ := worktreeFixture(t)
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	mux := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: worktreehunter.New(st, home, worktreehunter.Options{})}).buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	if rec := do(http.MethodPost, "/worktrees/remove", `{"path":"relative","async":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("relative async: %d", rec.Code)
	}
	for _, p := range []string{clean, dirty} {
		rec := do(http.MethodPost, "/worktrees/remove", `{"path":"`+p+`","async":true}`)
		var out struct {
			Removal worktreehunter.Removal `json:"removal"`
		}
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Removal.State != worktreehunter.RemovalRunning {
			t.Fatalf("async %s: %d %s", filepath.Base(p), rec.Code, rec.Body.String())
		}
	}
	var rep worktreehunter.ScanReport
	deadline := time.Now().Add(20 * time.Second)
	for {
		if err := json.Unmarshal(do(http.MethodGet, "/worktrees", "").Body.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Removals[clean].State != worktreehunter.RemovalRunning && rep.Removals[dirty].State != worktreehunter.RemovalRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("removals still running: %+v", rep.Removals)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if c, d := rep.Removals[clean], rep.Removals[dirty]; c.State != worktreehunter.RemovalRemoved || d.State != worktreehunter.RemovalFailed || d.RowState != "keep" {
		t.Fatalf("outcomes: clean %+v dirty %+v", c, d)
	}
	if _, err := os.Stat(clean); err == nil {
		t.Fatal("clean worktree still on disk")
	}
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
	if strings.Contains(rec.Body.String(), `"daily"`) {
		t.Fatalf("ledger without ?days carries a daily series: %s", rec.Body.String())
	}
	// ?days adds the daily series ending today; today holds the removal.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cleanup/ledger?days=7", nil))
	var daily struct {
		Daily []model.CleanupDay `json:"daily"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &daily) != nil || len(daily.Daily) != 7 ||
		daily.Daily[6].Day != time.Now().Format(time.DateOnly) || daily.Daily[6].Bytes != ledger.Totals.Bytes || daily.Daily[6].Count != ledger.Totals.Count {
		t.Fatalf("ledger daily: %d %s", rec.Code, rec.Body.String())
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
	if !apiroutes.IsMutation(http.MethodPost, "/worktrees/remove") || !apiroutes.ConsoleAllowed(http.MethodPost, "/worktrees/remove") {
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
	if !apiroutes.IsMutation(http.MethodPost, "/worktrees/advise") || !apiroutes.ConsoleAllowed(http.MethodPost, "/worktrees/advise") {
		t.Fatal("/worktrees/advise must be a console-admitted mutation")
	}

	unwired := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: hunter}).buildMux()
	rec = httptest.NewRecorder()
	unwired.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/advise", strings.NewReader(`{"path":"`+dirty+`"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("advise without an advisor: %d, want 503", rec.Code)
	}
}

func TestWorktreeAskEndpoint(t *testing.T) {
	home, root, repo, clean, dirty, _ := worktreeFixture(t)
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' '{\"result\":\"Nothing needed.\\nWORKTREE-VERDICT: removable scratch file only\",\"total_cost_usd\":0.05}'\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(bin, "claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	asker := agentask.New(st, home).WithBinDirs([]string{bin})
	hunter := worktreehunter.New(st, home, worktreehunter.Options{})
	mux := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: hunter, Asker: asker}).buildMux()
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
		{`{"path":"` + repo + `"}`, http.StatusNotFound},  // main worktree
		{`{"path":"` + clean + `"}`, http.StatusConflict}, // state remove: nothing to sort out
		{`{"path":"` + dirty + `"}`, http.StatusConflict}, // no agent is working here
	} {
		if rec := do(http.MethodPost, "/worktrees/ask", c.body); rec.Code != c.want {
			t.Fatalf("ask %s: %d %s, want %d", c.body, rec.Code, rec.Body.String(), c.want)
		}
	}
	now := time.Now()
	st.UpsertSession(model.Session{ID: "0199aaaa-bbbb-cccc-dddd-eeeeffff0000", Harness: "claude", Workspace: dirty,
		StartedAt: now, LastSeenAt: now, Confidence: model.ConfHook})
	rec := do(http.MethodPost, "/worktrees/ask", `{"path":"`+dirty+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"running"`) {
		t.Fatalf("ask dirty: %d %s", rec.Code, rec.Body.String())
	}
	asker.Wait()

	var asks []model.AgentAsk
	if err := json.Unmarshal(do(http.MethodGet, "/worktrees/asks", "").Body.Bytes(), &asks); err != nil || len(asks) != 1 ||
		asks[0].Verdict != "removable" || asks[0].Detail != "scratch file only" || asks[0].CostUSD != 0.05 {
		t.Fatalf("asks = %+v (%v)", asks, err)
	}
	if rec := do(http.MethodPost, "/worktrees/repos", `{"path":"`+repo+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("add repo: %d", rec.Code)
	}
	var rep worktreehunter.ScanReport
	if err := json.Unmarshal(do(http.MethodGet, "/worktrees?refresh=1", "").Body.Bytes(), &rep); err != nil || rep.Asks[dirty].Verdict != "removable" || rep.Askable[dirty] != "claude" {
		t.Fatalf("report asks = %+v, askable = %+v (%v)", rep.Asks, rep.Askable, err)
	}
	for _, p := range []string{"/worktrees/ask", "/worktrees/asks"} {
		for _, r := range apiroutes.Table {
			if r.Path == p && (!r.NoAgent || !r.Console) {
				t.Errorf("%s must be console-admitted and NoAgent", p)
			}
		}
	}
	if !apiroutes.IsMutation(http.MethodPost, "/worktrees/ask") {
		t.Fatal("/worktrees/ask must be a mutation")
	}
}

func TestWorktreeReviewTrashEndpoint(t *testing.T) {
	home, root, repo, clean, dirty, _ := worktreeFixture(t)
	excludes := filepath.Join(root, "excludes")
	if err := os.WriteFile(excludes, []byte(".env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "config", "core.excludesfile", excludes).CombinedOutput(); err != nil {
		t.Fatalf("set excludes: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(clean, ".env"), []byte("TOKEN=[REDACTED]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	hunter := worktreehunter.New(st, home, worktreehunter.Options{})
	row, _, err := hunter.Inspect(t.Context(), clean)
	if err != nil || row.State != worktreehunter.StateReview {
		t.Fatalf("review row: %+v, %v", row, err)
	}
	mux := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: hunter}).buildMux()
	post := func(head string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"path": clean, "head": head, "reasons": row.Reasons})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/review-trash", strings.NewReader(string(body))))
		return rec
	}
	if rec := post("stale"); rec.Code != http.StatusConflict {
		t.Fatalf("stale review: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(row.Head); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"trash_path"`) {
		t.Fatalf("reviewed Trash: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(clean); !os.IsNotExist(err) {
		t.Fatalf("worktree still present: %v", err)
	}
	// A keep row (an untracked file) goes to the Trash the same way.
	keep, _, err := hunter.Inspect(t.Context(), dirty)
	if err != nil || keep.State != worktreehunter.StateKeep {
		t.Fatalf("keep row: %+v, %v", keep, err)
	}
	body, _ := json.Marshal(map[string]any{"path": dirty, "head": keep.Head, "reasons": keep.Reasons})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/review-trash", strings.NewReader(string(body))))
	if rec.Code != http.StatusOK {
		t.Fatalf("keep row to the Trash: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(dirty); !os.IsNotExist(err) {
		t.Fatalf("keep worktree still present: %v", err)
	}
	if !apiroutes.IsMutation(http.MethodPost, "/worktrees/review-trash") || !apiroutes.ConsoleAllowed(http.MethodPost, "/worktrees/review-trash") {
		t.Fatal("review-trash must be a console-admitted mutation")
	}
}

// An orphan folder (its repository deleted) is listed; reveal opens it in
// Finder, reconnect refuses with nothing to reconnect to, trash moves it to
// the Trash. Paths the report does not list are refused.
func TestWorktreeOrphanEndpoints(t *testing.T) {
	home, root, repo, _, _, _ := worktreeFixture(t)
	orphan := filepath.Join(root, "agents", "lost")
	if out, err := exec.Command("git", "-C", repo, "worktree", "add", "-q", "-b", "feat/lost", orphan, "main").CombinedOutput(); err != nil {
		t.Fatalf("worktree add: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(orphan, "notes.txt"), []byte("only copy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(repo, ".git", "worktrees", "lost")); err != nil {
		t.Fatal(err)
	}
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	st.UpsertSession(model.Session{ID: "s-lost", Harness: "claude", Workspace: orphan, Status: model.SessionEnded,
		StartedAt: time.Now().Add(-72 * time.Hour), LastSeenAt: time.Now().Add(-72 * time.Hour)})
	a := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: worktreehunter.New(st, home, worktreehunter.Options{})})
	var opened []string
	a.openPath = func(args ...string) error { opened = append(opened, strings.Join(args, " ")); return nil }
	mux := a.buildMux()
	do := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		method := http.MethodPost
		if body == "" {
			method = http.MethodGet
		}
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	var rep worktreehunter.ScanReport
	if err := json.Unmarshal(do("/worktrees", "").Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rep.Repos {
		for _, w := range r.Worktrees {
			found = found || (w.Path == orphan && w.Orphan)
		}
	}
	if !found {
		t.Fatalf("orphan not listed: %+v", rep.Repos)
	}

	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/worktrees/reveal", `{"path":"relative"}`, http.StatusBadRequest},
		{"/worktrees/reveal", `{"path":"/not/listed"}`, http.StatusNotFound},
		{"/worktrees/reveal", `{"path":"` + orphan + `"}`, http.StatusOK},
		{"/worktrees/reconnect", `{"path":"` + orphan + `"}`, http.StatusConflict},
		{"/worktrees/reconnect", `{"path":"` + repo + `"}`, http.StatusNotFound},
		{"/worktrees/trash", `{"path":"` + repo + `"}`, http.StatusNotFound},
	} {
		if rec := do(c.path, c.body); rec.Code != c.want {
			t.Fatalf("POST %s %s: %d %s, want %d", c.path, c.body, rec.Code, rec.Body.String(), c.want)
		}
	}
	if len(opened) != 1 || opened[0] != "-R "+orphan {
		t.Fatalf("opened = %q", opened)
	}
	rec := do("/worktrees/trash", `{"path":"`+orphan+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"trash_path"`) {
		t.Fatalf("trash: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(orphan); err == nil {
		t.Fatal("orphan still on disk")
	}
	if rec := do("/worktrees/reveal", `{"path":"`+orphan+`"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("reveal after trash: %d, want 404", rec.Code)
	}
	for _, p := range []string{"/worktrees/reveal", "/worktrees/reconnect", "/worktrees/trash"} {
		if !apiroutes.IsMutation(http.MethodPost, p) || !apiroutes.ConsoleAllowed(http.MethodPost, p) {
			t.Fatalf("%s must be a console-admitted mutation", p)
		}
	}
}

// A group ask answers 202 at once with the row counts; one background run
// hands every keep, review and remove row of the cached report to the
// advisor, and a second ask for the same repository waits for it.
func TestWorktreeAdviseWholeRepository(t *testing.T) {
	home, _, repo, clean, dirty, gone := worktreeFixture(t)
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	var mu sync.Mutex
	var queued []model.WorktreeAdviceRequest
	answer, panicOn := true, 0
	hunter := worktreehunter.New(st, home, worktreehunter.Options{})
	a := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: hunter,
		WorktreeAdvisor: func(r model.WorktreeAdviceRequest) bool {
			mu.Lock()
			defer mu.Unlock()
			queued = append(queued, r)
			if len(queued) == panicOn {
				panic("advisor hook failed")
			}
			return answer
		}})
	oldPoll := groupAdvisePoll
	groupAdvisePoll = 5 * time.Millisecond
	t.Cleanup(func() { groupAdvisePoll = oldPoll })
	// note stores the i-th request's note, as the advisor does when it answers.
	note := func(i int) {
		mu.Lock()
		r := queued[i]
		mu.Unlock()
		if err := st.PutAdvisorVerdict(advisor.WorktreeSubjectID(r.Path, r.Head), "worktree",
			model.AdvisorVerdict{Assessment: "keep", Rationale: "x", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	mux := a.buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(queued)
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	idle := func() bool {
		a.groupAdviseMu.Lock()
		defer a.groupAdviseMu.Unlock()
		return len(a.groupAdvise) == 0
	}
	if rec := do(http.MethodPost, "/worktrees/repos", `{"path":"`+repo+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("add repo: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/worktrees?refresh=1", ""); rec.Code != http.StatusOK {
		t.Fatalf("scan: %d %s", rec.Code, rec.Body.String())
	}

	for _, c := range []struct {
		body string
		want int
	}{
		{`{"repo":"relative"}`, http.StatusBadRequest},
		{`{"repo":"` + repo + `","path":"` + dirty + `"}`, http.StatusBadRequest},
		{`{}`, http.StatusBadRequest},
		{`{"repo":"/no/such/repo"}`, http.StatusNotFound},
	} {
		if rec := do(http.MethodPost, "/worktrees/advise", c.body); rec.Code != c.want {
			t.Fatalf("advise %s: %d %s, want %d", c.body, rec.Code, rec.Body.String(), c.want)
		}
	}
	if count() != 0 {
		t.Fatalf("refused asks reached the advisor: %+v", queued)
	}

	rec := do(http.MethodPost, "/worktrees/advise", `{"repo":"`+repo+`"}`)
	var out struct {
		Status  string   `json:"status"`
		Queued  int      `json:"queued"`
		Rows    int      `json:"rows"`
		Skipped int      `json:"skipped"`
		Paths   []string `json:"paths"`
	}
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Status != "accepted" || out.Queued != 1 ||
		out.Rows != 2 || out.Skipped != 0 || len(out.Paths) != 2 {
		t.Fatalf("group ask: %d %s, want 202 accepted queued 1 rows 2 skipped 0 (clean and dirty; gone is prune)", rec.Code, rec.Body.String())
	}
	// The first row is handed over before the answer; the next waits for its
	// note, so the advisor's shared queue never holds more than one.
	if count() != 1 {
		t.Fatalf("rows asked before the answer = %d, want 1", count())
	}
	// Longer than one inspection of the next row takes.
	for deadline := time.Now().Add(1500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if count() != 1 {
			t.Fatalf("the second row was asked before the first note: %d", count())
		}
	}
	if rec := do(http.MethodPost, "/worktrees/advise", `{"repo":"`+repo+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("second group ask while the first runs: %d %s, want 409", rec.Code, rec.Body.String())
	}
	note(0)
	waitFor("the second row", func() bool { return count() == 2 })
	note(1)
	waitFor("the run to end", idle)
	got := map[string]string{}
	for _, q := range queued {
		got[q.Path] = q.State
	}
	if len(got) != 2 || got[clean] != "remove" || got[dirty] != "keep" || got[gone] != "" {
		t.Fatalf("advisor requests = %v, want clean (remove) and dirty (keep)", got)
	}

	// An advisor that is off or busy says so at once, as a single ask does,
	// and leaves no run behind.
	mu.Lock()
	answer = false
	mu.Unlock()
	if rec := do(http.MethodPost, "/worktrees/advise", `{"repo":"`+repo+`"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"queued":0`) || !idle() {
		t.Fatalf("advisor off: %d %s idle=%v, want 200 queued 0 and no run", rec.Code, rec.Body.String(), idle())
	}
	if count() != 3 {
		t.Fatalf("advisor off: %d asks, want the one refused", count())
	}

	// A panic in the background run ends that run, never the daemon.
	mu.Lock()
	answer, panicOn = true, 5
	mu.Unlock()
	if rec := do(http.MethodPost, "/worktrees/advise", `{"repo":"`+repo+`"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("group ask after the run ended: %d %s", rec.Code, rec.Body.String())
	}
	note(3)
	waitFor("the panicking run to end", func() bool { return count() == 5 && idle() })

	// With only the prune row left, nothing is askable.
	for _, p := range []string{clean, dirty} {
		if out, err := exec.Command("git", "-C", repo, "worktree", "remove", "--force", p).CombinedOutput(); err != nil {
			t.Fatalf("git worktree remove: %v %s", err, out)
		}
	}
	// A hunter on a new store has no cached scan, so it reads the folders as
	// they are now.
	st2 := testStore(t)
	t.Cleanup(func() { st2.Close() })
	fresh := New(Deps{Store: st2, Status: func() Status { return Status{Running: true} }, Worktrees: worktreehunter.New(st2, home, worktreehunter.Options{}),
		WorktreeAdvisor: func(model.WorktreeAdviceRequest) bool { return true }}).buildMux()
	rec = httptest.NewRecorder()
	fresh.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/repos", strings.NewReader(`{"path":"`+repo+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("add repo: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	fresh.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/advise", strings.NewReader(`{"repo":"`+repo+`"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("group ask with no askable rows: %d %s, want 409", rec.Code, rec.Body.String())
	}

	unwired := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Worktrees: hunter}).buildMux()
	rec = httptest.NewRecorder()
	unwired.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/worktrees/advise", strings.NewReader(`{"repo":"`+repo+`"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("group ask without an advisor: %d, want 503", rec.Code)
	}
}

// A group ask covers keep, review and remove rows git still records, at most
// 40; the rest are counted as skipped.
// One group ask runs at a time across repositories, so the advisor's shared
// queue holds at most one of its notes.
func TestGroupAdviseOneAtATime(t *testing.T) {
	a := &API{}
	if !a.startGroupAdvise("/a") || a.startGroupAdvise("/b") || a.startGroupAdvise("/a") {
		t.Fatal("a second group ask started while one runs")
	}
	a.finishGroupAdvise("/a")
	if !a.startGroupAdvise("/b") {
		t.Fatal("a group ask could not start after the last one finished")
	}
}

// A group ask's background run ends with the daemon: it runs under the
// serving context, not the request's.
func TestGroupAdviseRunsUnderTheServingContext(t *testing.T) {
	a := &API{}
	if a.lifetime().Err() != nil {
		t.Fatal("before serving, the lifetime is Background")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = a.ServeListener(ctx, ln)
	if a.lifetime().Err() == nil {
		t.Fatal("the lifetime is not the serving context")
	}
}

func TestGroupAdvisePathsCapsAndSkipsUnaskableRows(t *testing.T) {
	repo := worktreehunter.RepoReport{Path: "/r", Worktrees: []worktreehunter.Worktree{
		{Path: "/r", State: worktreehunter.StateMain},
		{Path: "/r/gone", State: worktreehunter.StatePrune},
		{Path: "/r/orphan", State: worktreehunter.StateReview, Orphan: true},
	}}
	states := []string{worktreehunter.StateKeep, worktreehunter.StateReview, worktreehunter.StateRemove}
	for i := range 43 {
		repo.Worktrees = append(repo.Worktrees, worktreehunter.Worktree{Path: fmt.Sprintf("/r/w%02d", i), State: states[i%3]})
	}
	paths, skipped := groupAdvisePaths(repo)
	if len(paths) != groupAdviseMaxRows || skipped != 3 || paths[0] != "/r/w00" || paths[len(paths)-1] != "/r/w39" {
		t.Fatalf("paths = %d (%v … %v), skipped %d; want 40 askable rows in report order and 3 skipped", len(paths), paths[0], paths[len(paths)-1], skipped)
	}
	if p, s := groupAdvisePaths(worktreehunter.RepoReport{Worktrees: repo.Worktrees[:3]}); len(p) != 0 || s != 0 {
		t.Fatalf("main, prune and orphan rows are not askable: %v %d", p, s)
	}
}
