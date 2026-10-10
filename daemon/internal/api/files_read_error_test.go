package api

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestFileDetailRejectsUnreadableEvidenceAndRecovers(t *testing.T) {
	for _, tc := range []struct{ name, damage, repair string }{
		{"flag scan", "UPDATE flags SET severity='invalid'", "UPDATE flags SET severity=3"},
		{"incident decode", "UPDATE incidents SET report_json='invalid /w/read-test.jsonl'", ""},
		{"access scan", "UPDATE events SET pid='invalid'", "UPDATE events SET pid=1"},
		{"incident query", "ALTER TABLE incidents RENAME TO unavailable_incidents", "ALTER TABLE unavailable_incidents RENAME TO incidents"},
		{"access query", "ALTER TABLE events RENAME TO unavailable_events", "ALTER TABLE unavailable_events RENAME TO events"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "evidence.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			const path = "/w/read-test.jsonl"
			now := time.Now()
			if _, err := st.PutFlag(model.Flag{ID: "f1", TS: now, Severity: 3, Evidence: []model.EvidenceItem{{Label: path}}}); err != nil {
				t.Fatal(err)
			}
			inc := model.IncidentReport{ID: "i1", Timestamp: now, TouchedFiles: []string{path}}
			if err := st.PutIncident(inc); err != nil {
				t.Fatal(err)
			}
			if _, err := st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now, PID: 1, Path: path, SessionID: "s1"}); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var savedReport string
			if err := db.QueryRow("SELECT report_json FROM incidents WHERE id='i1'").Scan(&savedReport); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tc.damage); err != nil {
				t.Fatal(err)
			}
			if w, _ := getDetail(t, a, path); w.Code != http.StatusServiceUnavailable {
				t.Errorf("unavailable evidence: %d %s", w.Code, w.Body.String())
			}
			if tc.repair != "" {
				if _, err := db.Exec(tc.repair); err != nil {
					t.Fatal(err)
				}
			} else if _, err := db.Exec("UPDATE incidents SET report_json=? WHERE id='i1'", savedReport); err != nil {
				t.Fatal(err)
			}
			w, detail := getDetail(t, a, path)
			if w.Code != http.StatusOK || len(detail.Findings) != 2 || len(detail.Accesses) != 1 {
				t.Fatalf("recovered detail: status=%d findings=%d accesses=%d", w.Code, len(detail.Findings), len(detail.Accesses))
			}
		})
	}
}

func TestFileDetailUnavailableStoreIsNotMissingEvidence(t *testing.T) {
	st := testStore(t)
	st.Close()
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	if w, _ := getDetail(t, a, "/w/missing.jsonl"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed store: %d %s", w.Code, w.Body.String())
	}
}
