package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

func TestCleanupEndpoints(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	home, repo := filepath.Join(root, "home"), filepath.Join(root, "ws", "app")
	for p, n := range map[string]int{
		filepath.Join(repo, ".tmp", "a.log"):        4000,
		filepath.Join(repo, ".quarantine", "b.bin"): 2000,
		filepath.Join(home, "placeholder"):          1,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(".tmp/\n.quarantine/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", repo, "init", "-q", "-b", "main")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+filepath.Join(root, "gitconfig"), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	c := clutter.New(st, home, func(context.Context) []clutter.Place {
		return []clutter.Place{{Path: repo, Project: repo}}
	})
	mux := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Clutter: c}).buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	rec := do(http.MethodGet, "/cleanup?refresh=1", "")
	var rep clutter.ClutterReport
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil {
		t.Fatalf("GET /cleanup: %d %s", rec.Code, rec.Body.String())
	}
	kinds := map[string]string{}
	for _, it := range rep.Items {
		kinds[it.Path] = it.Kind
	}
	if kinds[filepath.Join(repo, ".tmp")] != clutter.KindTmp || kinds[filepath.Join(repo, ".quarantine")] != clutter.KindQuarantine || rep.Reclaimed == nil {
		t.Fatalf("inventory = %+v", rep)
	}

	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/cleanup/trash", `{}`, http.StatusBadRequest},
		{"/cleanup/trash", `{"path":"` + filepath.Join(repo, "src") + `"}`, http.StatusNotFound},
		{"/cleanup/clean", `{"name":"npm"}`, http.StatusNotFound},
		{"/cleanup", ``, http.StatusMethodNotAllowed},
	} {
		if rec := do(http.MethodPost, c.path, c.body); rec.Code != c.want {
			t.Fatalf("POST %s %s: %d %s, want %d", c.path, c.body, rec.Code, rec.Body.String(), c.want)
		}
	}

	rec = do(http.MethodPost, "/cleanup/trash", `{"path":"`+filepath.Join(repo, ".tmp")+`"}`)
	var out struct {
		Result clutter.ClutterResult `json:"result"`
	}
	// ~/.Trash on macOS, the freedesktop ~/.local/share/Trash/files elsewhere.
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Result.Bytes < 4000 ||
		!strings.HasPrefix(out.Result.TrashAt, home+"/") || !strings.Contains(out.Result.TrashAt, "Trash") {
		t.Fatalf("trash: %d %s", rec.Code, rec.Body.String())
	}
	var ledger struct {
		Totals  model.CleanupTotals  `json:"totals"`
		Entries []model.CleanupEntry `json:"entries"`
	}
	if err := json.Unmarshal(do(http.MethodGet, "/cleanup/ledger", "").Body.Bytes(), &ledger); err != nil ||
		len(ledger.Entries) != 1 || ledger.Entries[0].Action != "trash:tmp" || ledger.Totals.TrashedBytes != out.Result.Bytes || ledger.Totals.Bytes != 0 {
		t.Fatalf("ledger = %+v", ledger)
	}

	for _, p := range []string{"/cleanup", "/cleanup/trash", "/cleanup/clean"} {
		found := false
		for _, r := range apiroutes.Table {
			if r.Path == p {
				found = true
				if !r.NoAgent || !r.Console {
					t.Errorf("%s must be console-admitted and NoAgent", p)
				}
			}
		}
		if !found {
			t.Errorf("%s missing from the route table", p)
		}
	}
	if !apiroutes.IsMutation(http.MethodPost, "/cleanup/trash") || !apiroutes.IsMutation(http.MethodPost, "/cleanup/clean") {
		t.Fatal("cleanup actions must be mutations")
	}
}

func TestCleanupAdviseEndpoint(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	home, repo := filepath.Join(root, "home"), filepath.Join(root, "ws", "app")
	for _, p := range []string{filepath.Join(repo, ".tmp", "a.log"), filepath.Join(home, ".cache", "someapp", "blob")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, make([]byte, 2000), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(".tmp/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", repo, "init", "-q", "-b", "main")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+filepath.Join(root, "gitconfig"), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	c := clutter.New(st, home, func(context.Context) []clutter.Place { return []clutter.Place{{Path: repo, Project: repo}} })
	var queued []model.ProjectCleanupRequest
	mux := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Clutter: c,
		Worktrees:      worktreehunter.New(st, home, worktreehunter.Options{}),
		ProjectAdvisor: func(r model.ProjectCleanupRequest) bool { queued = append(queued, r); return true }}).buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	if rec := do(http.MethodPost, "/cleanup/advise", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty payload: %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/cleanup/advise", `{"project":"/elsewhere"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d", rec.Code)
	}
	rec := do(http.MethodPost, "/cleanup/advise", `{"project":"`+repo+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"queued":true`) || len(queued) != 1 ||
		len(queued[0].Clutter) != 1 || queued[0].Clutter[0].Kind != "tmp" || queued[0].Clutter[0].Action != "trash" {
		t.Fatalf("advise: %d %s queued=%+v", rec.Code, rec.Body.String(), queued)
	}

	rec = do(http.MethodPost, "/cleanup/advise", `{"project":"machine"}`)
	if rec.Code != http.StatusOK || len(queued) != 2 || len(queued[1].Clutter) != 1 || queued[1].Clutter[0].Kind != "app-cache" {
		t.Fatalf("advise machine: %d %s queued=%+v", rec.Code, rec.Body.String(), queued)
	}

	st.PutAdvisorVerdict(advisor.ProjectSubjectID(repo), "project", model.AdvisorVerdict{Rationale: "Move .tmp to the Trash.", SuggestedAction: "Move .tmp to the Trash"})
	st.PutAdvisorVerdict(advisor.ProjectSubjectID("machine"), "project", model.AdvisorVerdict{Rationale: "Caches are small."})
	var rep clutter.ClutterReport
	if err := json.Unmarshal(do(http.MethodGet, "/cleanup", "").Body.Bytes(), &rep); err != nil ||
		rep.Advice[repo].Rationale != "Move .tmp to the Trash." || rep.Advice["machine"].Rationale != "Caches are small." {
		t.Fatalf("report advice = %+v (%v)", rep.Advice, err)
	}

	unwired := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Clutter: c}).buildMux()
	rec = httptest.NewRecorder()
	unwired.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/cleanup/advise", strings.NewReader(`{"project":"`+repo+`"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired: %d", rec.Code)
	}
	if !apiroutes.IsMutation(http.MethodPost, "/cleanup/advise") {
		t.Fatal("/cleanup/advise must be a mutation")
	}
}
