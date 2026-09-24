package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
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
		Result clutter.Result `json:"result"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Result.Bytes < 4000 || !strings.Contains(out.Result.TrashAt, ".Trash") {
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
