package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type incidentListReader interface {
	RecentIncidentDetails(int) ([]store.IncidentDetail, error)
}

type incidentFlagReader interface {
	GetFlag(string) (model.Flag, bool, error)
}

// currentIncidentReport derives priority only from retained structured evidence.
// Missing evidence preserves the report; read failure is surfaced to callers.
func currentIncidentReport(reader incidentFlagReader, inc model.IncidentReport) (model.IncidentReport, error) {
	if inc.Rule != "secret-in-transcript" || inc.AggregateCount != 1 || len(inc.RotateList) != 0 ||
		(inc.Risk != model.RiskHigh && inc.Risk != model.RiskMedium) {
		return inc, nil
	}
	f, found, err := reader.GetFlag(inc.FlagID)
	if err != nil || !found {
		return inc, err
	}
	return model.ProjectTranscriptIncident(inc, f), nil
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
