package api

import (
	"errors"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type incidentListReader interface {
	RecentIncidentsResult(int) ([]model.IncidentReport, error)
	IncidentStatusResult(string) (store.IncidentWorkflow, bool, error)
}

// readIncidentList joins each retained report to its workflow state.
// Failed or missing workflow evidence rejects the entire list.
func readIncidentList(reader incidentListReader, limit int) ([]snapshotIncident, error) {
	incidents, err := reader.RecentIncidentsResult(limit)
	if err != nil {
		return nil, err
	}
	out := make([]snapshotIncident, 0, len(incidents))
	for _, incident := range incidents {
		workflow, found, err := reader.IncidentStatusResult(incident.ID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("incident workflow unavailable")
		}
		out = append(out, snapshotIncident{IncidentReport: incident, Workflow: workflow})
	}
	return out, nil
}
