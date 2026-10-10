package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestIncidentLinkEnrichmentKeepsFlagsAndBatchFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incident-links.db")
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
	at := time.Now().UTC()
	for i, id := range []string{"bad", "good"} {
		if _, err := st.PutFlag(model.Flag{ID: id, Rule: "keychain-access", Severity: 3, TS: at.Add(-time.Duration(i) * time.Second), Evidence: []model.EvidenceItem{{Kind: "read", Label: "/work/credentials"}}}); err != nil {
			t.Fatal(err)
		}
		if err := st.PutIncident(model.IncidentReport{ID: id + "-incident", FlagID: id, Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	var original string
	if err := db.QueryRow(`SELECT report_json FROM incidents WHERE id='bad-incident'`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE incidents SET report_json='null' WHERE id='bad-incident'`); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	request := func(path string) []model.Flag {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var flags []model.Flag
		if path == "/flags" {
			err = json.Unmarshal(w.Body.Bytes(), &flags)
		} else {
			var f model.Flag
			err = json.Unmarshal(w.Body.Bytes(), &f)
			flags = []model.Flag{f}
		}
		if err != nil {
			t.Fatal(err)
		}
		return flags
	}
	link := func(f model.Flag) string {
		t.Helper()
		if f.Explain == nil || len(f.Evidence) != 1 {
			t.Fatalf("core flag or explanation lost: %+v", f)
		}
		for _, act := range f.Explain.Actions {
			if act.ID == "open-incident" {
				return act.Path
			}
		}
		return ""
	}
	flags := request("/flags")
	if len(flags) != 2 || flags[0].ID != "bad" || flags[1].ID != "good" {
		t.Fatalf("core flag order changed: %+v", flags)
	}
	if link(flags[0]) != "" || !strings.Contains(link(flags[1]), "good-incident") {
		t.Error("corrupt link survived or healthy sibling link was lost")
	}
	if h := st.WriteHealth(); h.ReadFailures != 1 || !slices.Contains(h.ReadActive, "incident links") {
		t.Errorf("healthy sibling hid batch read failure: %+v", h)
	}
	if link(request("/flags/bad/explain")[0]) != "" {
		t.Error("detail exposed corrupt report link")
	}
	h := st.WriteHealth()
	if _, err := db.Exec(`UPDATE incidents SET report_json=? WHERE id='bad-incident'`, original); err != nil {
		t.Fatal(err)
	}
	flags = request("/flags")
	if !strings.Contains(link(flags[0]), "bad-incident") {
		t.Error("repaired link did not return")
	}
	if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
		t.Errorf("recovery lost failure history: %+v", got)
	}
}
