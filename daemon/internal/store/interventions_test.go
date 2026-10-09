package store

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func interventionTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestInterventionReservationIsDurableAndCannotReplay(t *testing.T) {
	st := interventionTestStore(t)
	r := model.InterventionReceipt{ID: "intent", SessionKey: "family", Revision: 1, Kind: "terminate", RequestedAt: time.Now(), Status: "requested", Verification: "unknown"}
	ok, err := st.ReserveIntervention(r)
	if err != nil || !ok {
		t.Fatalf("reservation: %v %v", ok, err)
	}
	ok, err = st.ReserveIntervention(r)
	if err != nil || ok {
		t.Fatalf("replayed intent: %v %v", ok, err)
	}
	r.Revision = 2
	r.Status = "applied"
	r.Verification = "pending"
	if err := st.SaveIntervention(r); err != nil {
		t.Fatal(err)
	}
	r.Revision = 1
	r.Status = "requested"
	if err := st.SaveIntervention(r); err == nil {
		t.Fatal("stale result overwrote durable action")
	}
	rows, err := st.RecentInterventions("", 20)
	if err != nil || len(rows) != 1 || rows[0].Status != "applied" {
		t.Fatalf("result: %+v %v", rows, err)
	}
}

func TestInterventionWriteFailureAppearsInEvidenceHealth(t *testing.T) {
	st := interventionTestStore(t)
	st.db.Close()
	_, err := st.ReserveIntervention(model.InterventionReceipt{ID: "intent", Revision: 1, Status: "requested"})
	if err == nil || len(st.WriteHealth().Active) == 0 {
		t.Fatalf("failure hidden: %v %+v", err, st.WriteHealth())
	}
}
