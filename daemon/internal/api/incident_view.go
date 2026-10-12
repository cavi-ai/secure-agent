package api

import "github.com/cavi-ai/secure-agent/daemon/internal/store"

type incidentListReader interface {
	RecentIncidentDetails(int) ([]store.IncidentDetail, error)
}

// readIncidentList reads reports with their workflows in one store operation.
// Failed evidence rejects the entire list; an empty list encodes as [].
func readIncidentList(reader incidentListReader, limit int) ([]store.IncidentDetail, error) {
	incidents, err := reader.RecentIncidentDetails(limit)
	if err != nil {
		return nil, err
	}
	if incidents == nil {
		incidents = []store.IncidentDetail{}
	}
	return incidents, nil
}
