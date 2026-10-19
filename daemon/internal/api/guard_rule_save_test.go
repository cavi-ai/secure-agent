package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestGuardRuleSaveFailureIsReportedNotAudited(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
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
	a := newTestAPI(Deps{Store: st, Guard: GuardDeps{Broker: guard.NewBroker(time.Second)}})
	answerAlways := func() guard.Decision {
		t.Helper()
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			a.handleGuardDecision(rec, httptest.NewRequest(http.MethodPost, "/guard/decision",
				strings.NewReader(`{"agent":"claude","tool":"Read","path":"/synthetic/key","rule_id":"fixture"}`)))
		}()
		deadline := time.Now().Add(time.Second)
		for len(a.guardBroker.Pending()) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		pending := a.guardBroker.Pending()
		if len(pending) != 1 {
			t.Fatal("prompt did not queue")
		}
		a.guardBroker.Resolve(pending[0].ID, guard.Decision{Verdict: "allow", Scope: "always"})
		<-done
		var d guard.Decision
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &d) != nil {
			t.Fatalf("decision: %d %s", rec.Code, rec.Body.String())
		}
		return d
	}
	counts := func() (rules, audits int, recorded string) {
		t.Helper()
		if err := db.QueryRow(`SELECT COUNT(*) FROM guard_rules`).Scan(&rules); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'guard-rule'`).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT scope FROM guard_decisions ORDER BY rowid DESC LIMIT 1`).Scan(&recorded); err != nil {
			t.Fatal(err)
		}
		return rules, audits, recorded
	}

	if _, err := db.Exec(`CREATE TRIGGER deny_rule_save BEFORE INSERT ON guard_rules BEGIN SELECT RAISE(ABORT,'fixture save denied'); END`); err != nil {
		t.Fatal(err)
	}
	if d := answerAlways(); d.Verdict != "allow" || d.Scope != "once" {
		t.Fatalf("unsaved rule must answer this request once: %+v", d)
	}
	if rules, audits, recorded := counts(); rules != 0 || audits != 0 || recorded != "once" {
		t.Fatalf("unsaved rule recorded as standing: rules=%d audits=%d scope=%q", rules, audits, recorded)
	}
	if h := st.WriteHealth(); !slices.Contains(h.Active, "guard rules") {
		t.Fatalf("failed save missing from write health: %+v", h)
	}

	if _, err := db.Exec(`DROP TRIGGER deny_rule_save`); err != nil {
		t.Fatal(err)
	}
	if d := answerAlways(); d.Scope != "always" {
		t.Fatalf("saved rule answer: %+v", d)
	}
	if rules, audits, recorded := counts(); rules != 1 || audits != 1 || recorded != "always" {
		t.Fatalf("saved rule: rules=%d audits=%d scope=%q", rules, audits, recorded)
	}
	if h := st.WriteHealth(); slices.Contains(h.Active, "guard rules") {
		t.Fatalf("successful save left the fault active: %+v", h)
	}
}
