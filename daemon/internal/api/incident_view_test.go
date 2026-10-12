package api

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type incidentWorkflowRead struct {
	workflow store.IncidentWorkflow
	found    bool
	err      error
}

type memoryIncidentListReader struct {
	incidents   []model.IncidentReport
	err         error
	workflows   map[string]incidentWorkflowRead
	limit       int
	workflowIDs []string
}

func (r *memoryIncidentListReader) RecentIncidentsResult(limit int) ([]model.IncidentReport, error) {
	r.limit = limit
	return r.incidents, r.err
}

func (r *memoryIncidentListReader) IncidentStatusResult(id string) (store.IncidentWorkflow, bool, error) {
	r.workflowIDs = append(r.workflowIDs, id)
	result := r.workflows[id]
	return result.workflow, result.found, result.err
}

func TestIncidentListReaderEmptyAndFailedSource(t *testing.T) {
	for _, limit := range []int{10, 50} {
		r := &memoryIncidentListReader{}
		rows, err := readIncidentList(r, limit)
		if err != nil || rows == nil || len(rows) != 0 || r.limit != limit || len(r.workflowIDs) != 0 {
			t.Fatalf("empty source: rows=%+v err=%v reader=%+v", rows, err, r)
		}
	}
	failed := errors.New("incident source unavailable")
	r := &memoryIncidentListReader{incidents: []model.IncidentReport{{ID: "partial"}}, err: failed}
	rows, err := readIncidentList(r, 10)
	if !errors.Is(err, failed) || rows != nil || len(r.workflowIDs) != 0 {
		t.Fatalf("failed source leaked rows or queried workflows: %+v, %v, %+v", rows, err, r.workflowIDs)
	}
}

func TestIncidentListReaderRejectsPartialWorkflowsAndRecovers(t *testing.T) {
	failed := errors.New("workflow unavailable")
	for _, workflowErr := range []error{nil, failed} {
		r := &memoryIncidentListReader{
			incidents: []model.IncidentReport{
				{ID: "newer", Timestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), PID: 42, AggregateCount: 3, Risk: model.RiskHigh},
				{ID: "middle"}, {ID: "older"},
			},
			workflows: map[string]incidentWorkflowRead{
				"newer":  {workflow: store.IncidentWorkflow{Status: "acknowledged", AcknowledgedAt: "2026-01-02T01:00:00Z"}, found: true},
				"middle": {workflow: store.IncidentWorkflow{Status: "resolved"}, found: workflowErr != nil, err: workflowErr},
				"older":  {workflow: store.IncidentWorkflow{Status: "open"}, found: true},
			},
		}
		rows, err := readIncidentList(r, 50)
		if err == nil || rows != nil || !reflect.DeepEqual(r.workflowIDs, []string{"newer", "middle"}) || (workflowErr != nil && !errors.Is(err, workflowErr)) {
			t.Fatalf("partial workflow list escaped: %+v, %v, reads=%v", rows, err, r.workflowIDs)
		}
		resolved := store.IncidentWorkflow{Status: "resolved", ResolvedAt: "2026-01-02T02:00:00Z", ResolutionNote: "Reviewed"}
		r.workflows["middle"] = incidentWorkflowRead{workflow: resolved, found: true}
		r.workflowIDs = nil
		rows, err = readIncidentList(r, 50)
		want := []snapshotIncident{
			{IncidentReport: r.incidents[0], Workflow: r.workflows["newer"].workflow},
			{IncidentReport: r.incidents[1], Workflow: resolved},
			{IncidentReport: r.incidents[2], Workflow: r.workflows["older"].workflow},
		}
		if err != nil || !reflect.DeepEqual(rows, want) || !reflect.DeepEqual(r.workflowIDs, []string{"newer", "middle", "older"}) {
			t.Fatalf("recovered list changed report order or workflow facts: %+v, %v, reads=%v", rows, err, r.workflowIDs)
		}
	}
}
