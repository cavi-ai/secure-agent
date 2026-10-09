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

func TestFileActionsRejectUnreadableEvidenceAndRecover(t *testing.T) {
	for _, tc := range []struct {
		name, damage, repair string
		flag                 bool
	}{
		{"finding scan", "UPDATE flags SET severity='invalid'", "UPDATE flags SET severity=3", true},
		{"finding query", "ALTER TABLE flags RENAME TO unavailable_flags", "ALTER TABLE unavailable_flags RENAME TO flags", true},
		{"access scan", "UPDATE events SET pid='invalid'", "UPDATE events SET pid=1", false},
		{"access query", "ALTER TABLE events RENAME TO unavailable_events", "ALTER TABLE unavailable_events RENAME TO events", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "actions.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			p, _ := writeTranscript(t, "one")
			if tc.flag {
				if _, err := st.PutFlag(model.Flag{ID: "f1", TS: time.Now(), Severity: 3, Evidence: []model.EvidenceItem{{Label: p}}}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: time.Now(), PID: 1, Path: p, SessionID: "s1"}); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			rec := &openRecorder{}
			a.openPath = rec.open
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(tc.damage); err != nil {
				t.Fatal(err)
			}
			for _, h := range []func(http.ResponseWriter, *http.Request){a.handleFileOpen, a.handleFileReveal} {
				if w := postFile(a, h, http.MethodPost, p); w.Code != http.StatusServiceUnavailable {
					t.Errorf("unavailable evidence: %d %s", w.Code, w.Body.String())
				}
			}
			if len(rec.calls) != 0 || len(st.RecentAudit(10)) != 0 {
				t.Errorf("failed lookup ran or recorded a file action: %v", rec.calls)
			}
			if _, err := db.Exec(tc.repair); err != nil {
				t.Fatal(err)
			}
			for _, h := range []func(http.ResponseWriter, *http.Request){a.handleFileOpen, a.handleFileReveal} {
				if w := postFile(a, h, http.MethodPost, p); w.Code != http.StatusOK {
					t.Fatalf("recovered evidence: %d %s", w.Code, w.Body.String())
				}
			}
			if len(rec.calls) != 2 || len(st.RecentAudit(10)) != 2 {
				t.Fatalf("recovered actions missing: %v", rec.calls)
			}
		})
	}
}

func TestFileActionsUnavailableStoreIsNotMissingEvidence(t *testing.T) {
	st := testStore(t)
	st.Close()
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	rec := &openRecorder{}
	a.openPath = rec.open
	for _, h := range []func(http.ResponseWriter, *http.Request){a.handleFileOpen, a.handleFileReveal} {
		if w := postFile(a, h, http.MethodPost, "/w/missing.txt"); w.Code != http.StatusServiceUnavailable {
			t.Errorf("closed store: %d %s", w.Code, w.Body.String())
		}
	}
	if len(rec.calls) != 0 {
		t.Fatalf("closed store ran file actions: %v", rec.calls)
	}
}
