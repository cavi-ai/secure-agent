package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestCleanupInventoryLeavesOutUnreadableReclaimed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ledger.db")
	st, err := store.Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st.PutCleanup(model.CleanupEntry{Action: "worktree-remove", Path: "/r/.worktrees/a", Bytes: 9})
	c := clutter.New(st, t.TempDir(), func(context.Context) []clutter.Place { return nil })
	mux := newTestAPI(Deps{Store: st, Workspace: WorkspaceDeps{Clutter: c}}).buildMux()
	reclaimed := func() string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cleanup?refresh=1", nil))
		var body map[string]json.RawMessage
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("GET /cleanup: %d %s", rec.Code, rec.Body.String())
		}
		return string(body["reclaimed"])
	}
	if got := reclaimed(); !strings.Contains(got, `"bytes":9`) {
		t.Fatalf("readable ledger: reclaimed = %s", got)
	}
	if _, err := db.Exec(`ALTER TABLE cleanup_log RENAME TO unavailable_cleanup_log`); err != nil {
		t.Fatal(err)
	}
	if got := reclaimed(); got != "" {
		t.Fatalf("unreadable ledger shown as totals: %s", got)
	}
	if _, err := db.Exec(`ALTER TABLE unavailable_cleanup_log RENAME TO cleanup_log`); err != nil {
		t.Fatal(err)
	}
	if got := reclaimed(); !strings.Contains(got, `"bytes":9`) {
		t.Fatalf("repaired ledger: reclaimed = %s", got)
	}
}

func TestLedgerAndAskReadsDistinguishEmptyFromUnavailable(t *testing.T) {
	for route, empty := range map[string]string{
		"/worktrees/asks":        "[]",
		"/cleanup/ledger?days=2": `"entries":[]`,
	} {
		t.Run(route, func(t *testing.T) {
			st := testStore(t)
			t.Cleanup(func() { _ = st.Close() })
			mux := newTestAPI(Deps{Store: st}).buildMux()
			read := func() *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
				return rec
			}
			if rec := read(); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), empty) {
				t.Fatalf("empty history: status=%d body=%q", rec.Code, rec.Body.String())
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			rec := read()
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("unavailable history: status=%d body=%q", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "sql:") || strings.Contains(rec.Body.String(), "database") {
				t.Fatalf("storage diagnostic exposed: %q", rec.Body.String())
			}
		})
	}
}

func TestStatusUnactedCountUnknownWhenFlagsUnreadable(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { _ = st.Close() })
	mux := newTestAPI(Deps{Store: st, Status: func() Status { return Status{Running: true} }}).buildMux()
	read := func() string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /status = %d", rec.Code)
		}
		return rec.Body.String()
	}
	if body := read(); !strings.Contains(body, `"unacted_flags_24h":0`) {
		t.Fatalf("readable empty flags must count 0: %s", body)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if body := read(); !strings.Contains(body, `"unacted_flags_24h":null`) {
		t.Fatalf("unreadable flags must leave the count unknown: %s", body)
	}
}
