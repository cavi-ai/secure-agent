package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestGuardPendingWithoutAdvisorStore(t *testing.T) {
	a := &API{guardBroker: guard.NewBroker(time.Minute)}
	w := httptest.NewRecorder()
	a.handleGuardPending(w, httptest.NewRequest("GET", "/guard/pending", nil))
	if w.Code != 200 || w.Body.String() != "[]\n" {
		t.Fatalf("empty prompts without a store: %d %s", w.Code, w.Body.String())
	}
}

func TestGuardAdvisorReadBatchFailureAndRecovery(t *testing.T) {
	for _, damage := range []string{"corrupt", "unavailable"} {
		t.Run(damage, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "guard-advice.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			at := time.Now().UTC()
			broker := guard.NewBroker(time.Minute)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan guard.Decision, 3)
			started := 0
			t.Cleanup(func() {
				cancel()
				for i := 0; i < started; i++ {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("task-owned guard request did not stop")
						return
					}
				}
			})
			fixtures := []guard.Pending{
				{ID: "first", SessionID: "s1", Agent: "claude", RuleID: "env-files", Path: "/work/a/.env", Tool: "Read"},
				{ID: "second", SessionID: "s2", Agent: "claude", RuleID: "env-files", Path: "/work/a/.env", Tool: "Read"},
				{ID: "third", SessionID: "s3", Agent: "claude", RuleID: "env-files", Path: "/work/b/.env", Tool: "Read"},
			}
			for i, p := range fixtures {
				p.TS = at.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
				go func() { done <- broker.Request(ctx, p) }()
				started++
				deadline := time.Now().Add(time.Second)
				for len(broker.Pending()) != started {
					if time.Now().After(deadline) {
						t.Fatal("prompt did not register")
					}
					time.Sleep(time.Millisecond)
				}
				subject := advisor.GuardSubjectID(p.Agent, p.RuleID, p.Path, p.Tool)
				if err := st.PutAdvisorVerdict(subject, "guard", model.AdvisorVerdict{Assessment: "suspicious", Rationale: "stored", Confidence: .7, CreatedAt: at}); err != nil {
					t.Fatal(err)
				}
			}
			baseline := broker.Pending()
			firstID := advisor.GuardSubjectID(fixtures[0].Agent, fixtures[0].RuleID, fixtures[0].Path, fixtures[0].Tool)
			if damage == "corrupt" {
				_, err = db.Exec(`UPDATE advisor_verdicts SET created_at='invalid' WHERE subject_id=?`, firstID)
			} else {
				_, err = db.Exec(`ALTER TABLE advisor_verdicts RENAME TO unavailable_advice`)
			}
			if err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, nil)
			a.guardBroker = broker
			mux := a.buildMux()
			request := func() []guard.Pending {
				t.Helper()
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest("GET", "/guard/pending", nil))
				if w.Code != 200 {
					t.Fatalf("read: %d %s", w.Code, w.Body.String())
				}
				var rows []guard.Pending
				if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
					t.Fatal(err)
				}
				if len(rows) != len(baseline) {
					t.Fatalf("pending prompts lost: %+v", rows)
				}
				for i, row := range rows {
					row.Advisor = nil
					if !reflect.DeepEqual(row, baseline[i]) {
						t.Errorf("prompt fields or ordering changed: got %+v, want %+v", row, baseline[i])
					}
				}
				if !reflect.DeepEqual(broker.Pending(), baseline) || len(done) != 0 {
					t.Error("advice read mutated or resolved pending prompts")
				}
				return rows
			}
			rows := request()
			if rows[0].Advisor != nil || rows[1].Advisor != nil {
				t.Error("invalid advice was returned")
			}
			if damage == "corrupt" {
				if v := rows[2].Advisor; v == nil || v.Assessment != "suspicious" || v.Rationale != "stored" || v.Confidence != .7 || !v.CreatedAt.Equal(at) {
					t.Errorf("healthy sibling advice lost: %+v", v)
				}
			} else if rows[2].Advisor != nil {
				t.Error("unavailable advice was returned")
			}
			h := st.WriteHealth()
			if h.ReadFailures != 1 || !slices.Contains(h.ReadActive, "guard advisor verdicts") {
				t.Errorf("guard batch fault lost or counted per row: %+v", h)
			}
			if damage == "corrupt" {
				_, err = db.Exec(`UPDATE advisor_verdicts SET created_at=? WHERE subject_id=?`, at.Format(time.RFC3339Nano), firstID)
			} else {
				_, err = db.Exec(`ALTER TABLE unavailable_advice RENAME TO advisor_verdicts`)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range request() {
				if row.Advisor == nil || row.Advisor.Rationale != "stored" {
					t.Errorf("advice did not return after repair: %+v", row)
				}
			}
			if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
				t.Errorf("repair lost failure history: %+v", got)
			}
		})
	}
}
