package api

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryIncidentListReader struct {
	incidents []store.IncidentDetail
	err       error
	limit     int
	reads     int
}

func (r *memoryIncidentListReader) RecentIncidentDetails(limit int) ([]store.IncidentDetail, error) {
	r.limit = limit
	r.reads++
	return r.incidents, r.err
}

func TestIncidentListReaderEmptyAndFailedSource(t *testing.T) {
	for _, limit := range []int{10, 50} {
		r := &memoryIncidentListReader{}
		rows, err := readIncidentList(r, limit)
		if err != nil || rows == nil || len(rows) != 0 || r.limit != limit || r.reads != 1 {
			t.Fatalf("empty source: rows=%+v err=%v reader=%+v", rows, err, r)
		}
	}
	failed := errors.New("incident source unavailable")
	r := &memoryIncidentListReader{incidents: []store.IncidentDetail{{IncidentReport: model.IncidentReport{ID: "partial"}}}, err: failed}
	rows, err := readIncidentList(r, 10)
	if !errors.Is(err, failed) || rows != nil || r.reads != 1 {
		t.Fatalf("failed source leaked rows: %+v, %v, %+v", rows, err, r)
	}
}

func TestIncidentListReaderRejectsPartialWorkflowsAndRecovers(t *testing.T) {
	failed := errors.New("workflow unavailable")
	want := []store.IncidentDetail{
		{IncidentReport: model.IncidentReport{ID: "newer", Timestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), PID: 42, AggregateCount: 3, Risk: model.RiskHigh}, Workflow: store.IncidentWorkflow{Status: "acknowledged", AcknowledgedAt: "2026-01-02T01:00:00Z"}},
		{IncidentReport: model.IncidentReport{ID: "middle"}, Workflow: store.IncidentWorkflow{Status: "resolved", ResolvedAt: "2026-01-02T02:00:00Z", ResolutionNote: "Reviewed"}},
		{IncidentReport: model.IncidentReport{ID: "older"}, Workflow: store.IncidentWorkflow{Status: "open"}},
	}
	r := &memoryIncidentListReader{incidents: want[:1], err: failed}
	rows, err := readIncidentList(r, 50)
	if !errors.Is(err, failed) || rows != nil || r.reads != 1 {
		t.Fatalf("partial workflow list escaped: %+v, %v, reads=%d", rows, err, r.reads)
	}
	r.incidents, r.err = want, nil
	rows, err = readIncidentList(r, 50)
	if err != nil || !reflect.DeepEqual(rows, want) || r.reads != 2 || r.limit != 50 {
		t.Fatalf("recovered list changed report order or workflow facts: %+v, %v, reads=%d", rows, err, r.reads)
	}
}
