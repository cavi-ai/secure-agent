package api

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestUnavailableFlagDetailDoesNotApplyExceptions(t *testing.T) {
	for _, surface := range []string{"explain", "single exception", "batch exception"} {
		t.Run(surface, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "flags.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			a.expected = correlate.NewExpectStore(filepath.Join(dir, "expected.json"))
			bad := ghFlag("bad-detail", time.Now(), ghRead("sensitive read", 900, "GitHub"), "evil.example.com")
			good := ghFlag("good-detail", time.Now(), ghRead("sensitive read", 901, "GitHub"), "good.example.com")
			if _, err := st.PutFlag(bad); err != nil {
				t.Fatal(err)
			}
			if _, err := st.PutFlag(good); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("UPDATE flags SET pid='invalid' WHERE id=?", bad.ID); err != nil {
				t.Fatal(err)
			}
			method, endpoint, body := "GET", "/flags/bad-detail/explain", ""
			if surface == "single exception" {
				method, endpoint, body = "POST", "/expected", `{"flag_id":"bad-detail"}`
			}
			if surface == "batch exception" {
				method, endpoint, body = "POST", "/expected", `{"flag_ids":["good-detail","bad-detail"]}`
			}
			w := httptest.NewRecorder()
			a.buildMux().ServeHTTP(w, httptest.NewRequest(method, endpoint, strings.NewReader(body)))
			if w.Code != 503 {
				t.Errorf("unavailable detail: %d %s", w.Code, w.Body.String())
			}
			if len(a.expected.List()) != 0 {
				t.Error("unavailable source allowed a partial exception edit")
			}
			if audits := st.RecentAudit(10); len(audits) != 0 {
				t.Errorf("failed edit wrote audit: %+v", audits)
			}
			if labels, err := st.SimilarLabelsResult(readConnectRule, "", "", 10); err != nil || len(labels) != 0 {
				t.Errorf("failed edit wrote labels: %+v %v", labels, err)
			}
			var acknowledged int
			if err := db.QueryRow("SELECT COUNT(*) FROM flags WHERE acknowledged IS NOT NULL AND acknowledged!=''").Scan(&acknowledged); err != nil || acknowledged != 0 {
				t.Errorf("failed edit acknowledged sources: %d %v", acknowledged, err)
			}
			if _, err := st.PutFlag(bad); err != nil {
				t.Fatal(err)
			}
			w = httptest.NewRecorder()
			a.buildMux().ServeHTTP(w, httptest.NewRequest(method, endpoint, strings.NewReader(body)))
			if w.Code != 200 {
				t.Errorf("recovery: %d %s", w.Code, w.Body.String())
			}
			if surface == "explain" {
				w = httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/flags/missing/explain", nil))
				if w.Code != 404 {
					t.Errorf("missing flag: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
}
