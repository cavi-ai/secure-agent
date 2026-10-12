package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSnapshotIncidentRoundTripPreservesIntegerEvidence(t *testing.T) {
	// Generic interface decoding rounds this valid integer through float64.
	// Raw JSON avoids compile-time overflow on platforms with smaller ints.
	raw := []byte(`{"incidents":[{"id":"incident","flag_id":"flag","pid":42,"agent":"claude","timestamp":"2026-10-11T12:00:00Z","rule":"secret-file","aggregate_count":9007199254740993,"summary":"Observed read","risk":"HIGH","touched_files":[],"connections":[],"rotate_list":[],"workflow":{"status":"acknowledged","acknowledged_at":"2026-10-11T12:01:00Z"}}]}`)
	if ^uint(0)>>63 == 0 {
		t.Skip("aggregate count fixture requires a 64-bit int")
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var original, roundTrip struct {
		Incidents json.RawMessage `json:"incidents"`
	}
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	decode := func(raw json.RawMessage) any {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if !reflect.DeepEqual(decode(original.Incidents), decode(roundTrip.Incidents)) {
		t.Fatalf("incident evidence changed during snapshot round trip:\nwant %s\ngot  %s", original.Incidents, roundTrip.Incidents)
	}
}

func TestSnapshotRejectsInvalidIncidentTypes(t *testing.T) {
	for _, incidents := range []string{
		`{}`, `"invalid"`, `[1]`, `[{"aggregate_count":1.5}]`, `[{"workflow":{"status":1}}]`,
	} {
		t.Run(incidents, func(t *testing.T) {
			var snap Snapshot
			if err := json.Unmarshal([]byte(`{"incidents":`+incidents+`}`), &snap); err == nil {
				t.Fatal("invalid incident field types accepted")
			}
		})
	}
}

func TestSnapshotIncidentWireShape(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	read := func() []snapshotIncident {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/snapshot", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("snapshot: %d %s", w.Code, w.Body.String())
		}
		var response struct {
			Incidents []snapshotIncident `json:"incidents"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Incidents
	}
	if got := read(); got == nil || len(got) != 0 {
		t.Fatalf("empty incidents must be []: %+v", got)
	}
	report := model.IncidentReport{ID: "incident", FlagID: "flag", PID: 42, Agent: "claude",
		Timestamp: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC), Rule: "secret-file",
		Summary: "Observed read", Risk: model.RiskHigh, TouchedFiles: []string{"/fixture/file"},
		Connections: []string{}, RotateList: []model.RotateItem{}}
	if err := st.PutIncident(report); err != nil {
		t.Fatal(err)
	}
	wf, updated, err := st.SetIncidentStatusResult(report.ID, "acknowledged", "")
	if err != nil || !updated {
		t.Fatalf("acknowledge: updated=%v err=%v", updated, err)
	}
	// Report fields stay flattened; workflow stays a separate nested object.
	stored, err := st.RecentIncidentsResult(10)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored reports: %+v err=%v", stored, err)
	}
	want := []snapshotIncident{{IncidentReport: stored[0], Workflow: wf}}
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatalf("incident response: got %+v want %+v", got, want)
	}
}
