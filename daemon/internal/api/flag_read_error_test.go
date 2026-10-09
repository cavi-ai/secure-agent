package api

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestFlagReadFailuresRejectPartialResponsesAndRecover(t *testing.T) {
	for _, damage := range []string{"pid='invalid'", "evidence='invalid'", "process='invalid'", "last_seen='invalid'"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "flags.db")
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
			for _, id := range []string{"bad", "good"} {
				if _, err := st.PutFlag(model.Flag{ID: id, Rule: readConnectRule, Severity: 3, PID: 1, Agent: "codex", TS: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec("UPDATE flags SET " + damage + " WHERE id='bad'"); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			for _, url := range []string{"/flags", "/patterns", "/snapshot"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if w.Code != 503 {
					t.Fatalf("%s returned partial flags as success: %d %s", url, w.Code, w.Body.String())
				}
			}
			if _, err := db.Exec("UPDATE flags SET pid=1, evidence='null', process=NULL, last_seen=NULL WHERE id='bad'"); err != nil {
				t.Fatal(err)
			}
			for _, url := range []string{"/flags", "/patterns", "/snapshot", "/flags?agent=empty"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if w.Code != 200 {
					t.Fatalf("%s did not recover: %d %s", url, w.Code, w.Body.String())
				}
				if url == "/flags?agent=empty" && w.Body.String() != "[]\n" {
					t.Fatalf("empty flags: %s", w.Body.String())
				}
			}
		})
	}
}

func TestSnapshotRejectsFailedPatternReadOutsideOpenFlagList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flags.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.PutFlag(model.Flag{ID: "reviewed", Rule: readConnectRule, Severity: 3, PID: 1, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE flags SET acknowledged='reviewed', evidence='invalid' WHERE id='reviewed'"); err != nil {
		t.Fatal(err)
	}
	if flags, err := st.QueryFlagsResult(store.FlagFilter{Unacted: true}); err != nil || len(flags) != 0 {
		t.Fatalf("open flag list: %+v, %v", flags, err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/snapshot", nil))
	if w.Code != 503 {
		t.Fatalf("snapshot hid failed pattern read: %d %s", w.Code, w.Body.String())
	}
}
