package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestReviewSourceTimestampRejectsTransactionsAndRecovers(t *testing.T) {
	for _, damage := range []struct {
		name  string
		value any
	}{{"null", nil}, {"empty", ""}, {"malformed", "invalid-time"}} {
		for _, operation := range []string{"sources", "acknowledge", "close_reported", "expect", "rekey"} {
			t.Run(damage.name+"/"+operation, func(t *testing.T) {
				s := reviewStore(t)
				for _, id := range []string{"first", "second"} {
					if _, err := s.PutFlag(reviewFlag(id)); err != nil {
						t.Fatal(err)
					}
				}
				r := onlyReview(t, s)
				if len(r.SourceIDs) != 2 {
					t.Fatalf("fixture requires two sources: %+v", r)
				}
				if _, err := s.db.Exec(`UPDATE flags SET ts=? WHERE id='second'`, damage.value); err != nil {
					t.Fatal(err)
				}
				before := reviewSourceDurableState(t, s)
				run := func(wantError bool) {
					t.Helper()
					var err error
					switch operation {
					case "sources":
						tx, e := s.db.Begin()
						if e != nil {
							t.Fatal(e)
						}
						got, e := reviewSourcesTx(tx, r.ID)
						tx.Rollback()
						err = e
						if wantError && got != nil {
							t.Errorf("corrupt source returned a usable batch: %+v", got)
						}
						if !wantError && len(got) != 2 {
							t.Errorf("repaired sources missing: %+v", got)
						}
					case "rekey":
						err = s.RekeySession("session", "canonical")
					default:
						req := model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: operation}
						if operation == "expect" {
							req.Scope = &model.ScopeChoice{Kind: "once"}
						}
						_, err = s.DecideFindingReview(req)
					}
					if (err != nil) != wantError {
						t.Errorf("%s error=%v; want rejection=%v", operation, err, wantError)
					}
				}
				run(true)
				if after := reviewSourceDurableState(t, s); after != before {
					t.Error("corrupt source changed durable session, flag, review, membership or receipt state")
				}
				// Equivalent RFC3339 offsets and fractional seconds remain supported.
				stamp := reviewFlag("second").TS.In(time.FixedZone("offset", 3600)).Format(time.RFC3339Nano)
				if _, err := s.db.Exec(`UPDATE flags SET ts=? WHERE id='second'`, stamp); err != nil {
					t.Fatal(err)
				}
				run(false)
			})
		}
	}
}

func TestReviewSourceTimestampPreservesNullableMetadata(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("nullable")
	f.TS = f.TS.Add(123456789 * time.Nanosecond)
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	r := onlyReview(t, s)
	if _, err := s.db.Exec(`UPDATE flags SET rule=NULL,severity=NULL,pid=NULL,agent=NULL,session_id=NULL,workspace=NULL,evidence=NULL WHERE id=?`, f.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	got, err := reviewSourcesTx(tx, r.ID)
	tx.Rollback()
	if err != nil || len(got) != 1 {
		t.Fatalf("nullable metadata: %+v %v", got, err)
	}
	v := got[0].flag
	if !v.TS.Equal(f.TS) || v.Rule != "" || v.Severity != 0 || v.PID != 0 || v.Agent != "" || v.SessionID != "" || v.Workspace != "" || len(v.Evidence) != 0 {
		t.Errorf("nullable metadata or timestamp precision changed: %+v", v)
	}
}

// Compare actual SQLite rows, including receipts and grants, across a rejected
// transaction rather than inferring atomicity from its returned error.
func reviewSourceDurableState(t *testing.T, s *Store) string {
	t.Helper()
	state := map[string][][]any{}
	for _, table := range []string{"sessions", "flags", "finding_reviews", "finding_review_members", "finding_review_actions", "decision_scope_receipts", "decision_scopes"} {
		rows, err := s.db.Query("SELECT * FROM " + table + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values, dest := make([]any, len(columns)), make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			state[table] = append(state[table], values)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
