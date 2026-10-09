package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionReportUnavailableIdentityIsNotNotFound(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	st.Close()
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/sessions/session/report?format=md", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), "session not found") {
		t.Fatalf("failed read returned %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionReportPartialExportNamesMissingEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpsertSession(model.Session{ID: "session", Harness: "codex", StartedAt: time.Now(), LastSeenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`ALTER TABLE events RENAME TO unavailable_events`); err != nil {
		t.Fatal(err)
	}
	mux := newTestAPI("", st, nil, func() Status { return Status{Running: true} }).buildMux()
	for _, format := range []string{"json", "md"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/session/report?format="+format, nil))
		if w.Code != 200 || w.Header().Get("X-Secure-Agent-Report-State") != "partial" {
			t.Fatalf("partial report: %d %+v", w.Code, w.Header())
		}
		if format == "json" {
			var rep store.SessionReport
			if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Evidence == nil || rep.Evidence.Events.Available || !rep.Evidence.Flags.Available {
				t.Fatalf("mixed read evidence lost: %+v", rep.Evidence)
			}
			continue
		}
		md := w.Body.String()
		if strings.Contains(mdSection(md, "## Summary"), "tool calls 0") || !strings.Contains(md, "Activity totals unavailable") {
			t.Fatalf("failed activity became zero activity: %s", md)
		}
		for _, heading := range []string{"## Models", "## Tools", "## Files touched", "## Network", "## Guard decisions", "## Secret hits", "## Timeline"} {
			if !strings.Contains(mdSection(md, heading), "unavailable") {
				t.Fatalf("%s hid missing evidence: %s", heading, mdSection(md, heading))
			}
		}
		if mdSection(md, "## Findings") != "none" {
			t.Fatal("valid empty findings did not remain independently available")
		}
	}
}

func TestSessionReportMarkdownPreservesDecisionAndResidualRisk(t *testing.T) {
	at := time.Now().UTC()
	rep := store.SessionReport{Reviews: []model.ReviewRecord{{ID: "review", Revision: 2, ReviewState: "unreviewed", EvidenceAvailable: false,
		Assessment: model.FindingAssessment{Risk: "high", Control: "observed-only", ResidualRisk: "possible-exposure"},
		Decision:   &model.ReviewDecisionReceipt{ID: "review", Revision: 1, Action: "acknowledge", At: at}}}}
	md := renderSessionMarkdown(rep)
	for _, want := range []string{"## Review decisions", "possible-exposure", "acknowledge", "revision 1", "earlier revision", "Source evidence unavailable", "does not establish task completion"} {
		if !strings.Contains(md, want) {
			t.Fatalf("missing %q from report: %s", want, md)
		}
	}
	rep.Reviews[0].EvidenceAvailable = true
	if md := renderSessionMarkdown(rep); !strings.Contains(md, "Assessment source evidence unavailable") || !strings.Contains(md, "possible-exposure") {
		t.Fatalf("remaining weaker sources hid the unavailable assessment source: %s", md)
	}
}
