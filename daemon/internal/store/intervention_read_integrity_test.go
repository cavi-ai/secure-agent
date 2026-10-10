package store

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestInterventionReadsRejectCorruptReceiptsAndRecover(t *testing.T) {
	for _, tc := range []struct{ name, damage string }{
		{"null", `receipt_json='null'`},
		{"empty object", `receipt_json='{}'`},
		{"malformed JSON", `receipt_json='invalid'`},
		{"identity", `receipt_json=json_set(receipt_json,'$.id','other')`},
		{"session identity", `receipt_json=json_set(receipt_json,'$.session_id','other')`},
		{"session key", `receipt_json=json_set(receipt_json,'$.session_key','other')`},
		{"revision", `receipt_json=json_set(receipt_json,'$.revision',2)`},
		{"request time", `receipt_json=json_set(receipt_json,'$.requested_at','2026-01-01T00:00:00Z')`},
		{"index timestamp", `requested_at='invalid'`},
		{"index scan", `revision='invalid'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := interventionTestStore(t)
			at := time.Now().UTC()
			if err := st.UpsertSession(model.Session{ID: "s1", RootPID: 42, RootStartedAt: at.Format(time.RFC3339Nano), Harness: "codex", StartedAt: at, LastSeenAt: at}); err != nil {
				t.Fatal(err)
			}
			for i, id := range []string{"bad", "good"} {
				r := model.InterventionReceipt{ID: id, SessionKey: "family", RootPID: 42, RootStartedAt: at, Revision: 1, RequestedAt: at.Add(time.Duration(i) * time.Second), Status: "requested", Kind: "pause", Verification: "unknown"}
				if ok, err := st.ReserveIntervention(r); err != nil || !ok {
					t.Fatalf("reserve: %v, %v", ok, err)
				}
			}
			var raw, requestedAt string
			if err := st.db.QueryRow(`SELECT receipt_json,requested_at FROM interventions WHERE id='bad'`).Scan(&raw, &requestedAt); err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.Exec(`UPDATE interventions SET ` + tc.damage + ` WHERE id='bad'`); err != nil {
				t.Fatal(err)
			}
			if rows, err := st.RecentInterventions("s1", 200); err == nil || rows != nil {
				t.Errorf("corrupt receipt or partial history returned: %+v, %v", rows, err)
			}
			if h := st.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"intervention receipts"}) || h.Failures != 0 {
				t.Errorf("corrupt receipt health: %+v", h)
			}
			if rep, found, err := st.SessionReportResult("s1"); err != nil || !found || rep.InterventionsAvailable || rep.Evidence.Interventions.Available || len(rep.Interventions) != 0 || !rep.Evidence.Events.Available {
				t.Errorf("report accepted corrupt receipts or lost activity: %+v, %v, %v", rep, found, err)
			}
			if out := st.SessionOutcomes("s1"); out.Evidence.Interventions.Available || len(out.Interventions) != 0 || !out.Evidence.Incidents.Available || !out.Evidence.Reviews.Available {
				t.Errorf("outcomes accepted corrupt receipts or lost siblings: %+v", out)
			}
			failures := st.WriteHealth().ReadFailures
			if _, err := st.db.Exec(`UPDATE interventions SET receipt_json=?,requested_at=?,revision=1 WHERE id='bad'`, raw, requestedAt); err != nil {
				t.Fatal(err)
			}
			if rows, err := st.RecentInterventions("s1", 200); err != nil || len(rows) != 2 || rows[0].ID != "good" || rows[1].ID != "bad" {
				t.Fatalf("recovery: %+v, %v", rows, err)
			}
			if h := st.WriteHealth(); h.ReadFailures != failures || len(h.ReadActive) != 0 {
				t.Errorf("recovered health: %+v", h)
			}
		})
	}
}

func TestInterventionReadsPreserveEquivalentTimestampsAndEmptyHistory(t *testing.T) {
	st := interventionTestStore(t)
	if rows, err := st.RecentInterventions("missing", 200); err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("empty history: %+v, %v", rows, err)
	}
	at := time.Now().UTC()
	r := model.InterventionReceipt{ID: "intent", Revision: 1, RequestedAt: at, Status: "requested"}
	if ok, err := st.ReserveIntervention(r); err != nil || !ok {
		t.Fatalf("reserve: %v, %v", ok, err)
	}
	if _, err := st.db.Exec(`UPDATE interventions SET requested_at=? WHERE id='intent'`, at.In(time.FixedZone("offset", 3600)).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if rows, err := st.RecentInterventions("", 200); err != nil || len(rows) != 1 || !rows[0].RequestedAt.Equal(at) {
		t.Fatalf("equivalent time or optional fields rejected: %+v, %v", rows, err)
	}
}

func TestInterventionReadsPreserveRekeyedSessionIdentity(t *testing.T) {
	st := interventionTestStore(t)
	at := time.Now().UTC()
	if err := st.UpsertSession(model.Session{ID: "old", RootPID: 42, RootStartedAt: at.Format(time.RFC3339Nano), Harness: "codex", StartedAt: at, LastSeenAt: at}); err != nil {
		t.Fatal(err)
	}
	r := model.InterventionReceipt{ID: "intent", RootPID: 42, RootStartedAt: at, Revision: 1, RequestedAt: at, Status: "requested"}
	if ok, err := st.ReserveIntervention(r); err != nil || !ok {
		t.Fatalf("reserve: %v, %v", ok, err)
	}
	if err := st.RekeySession("old", "new"); err != nil {
		t.Fatal(err)
	}
	if rows, err := st.RecentInterventions("new", 200); err != nil || len(rows) != 1 || rows[0].SessionID != "new" {
		t.Fatalf("rekeyed receipt: %+v, %v", rows, err)
	}
	if rows, err := st.RecentInterventions("old", 200); err != nil || len(rows) != 0 {
		t.Fatalf("stale identity: %+v, %v", rows, err)
	}
}
