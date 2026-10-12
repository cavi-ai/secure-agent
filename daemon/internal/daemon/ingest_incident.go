package daemon

import (
	"fmt"

	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// absorbError marks a failed absorb lookup; its text is the store's error.
type absorbError struct{ err error }

func (e absorbError) Error() string { return e.err.Error() }
func (e absorbError) Unwrap() error { return e.err }

// incidentFor answers which incident a stored flag joined or created. Incidents
// aggregate: one per rule+session+subject, flags become its evidence. The
// 323-identical-flags storm becomes one incident with a count, not 323 reports.
// created is false when the flag joined an open incident. A failed lookup is an
// absorbError so callers never mistake it for permission to create a report.
func (i *eventIngest) incidentFor(fl model.Flag) (report model.IncidentReport, created bool, err error) {
	st := i.deps.Store
	subject := intel.SubjectForFlag(fl)
	joined, persisted, err := st.AbsorbOpenIncident(fl.Rule, fl.SessionID, subject, fl.ID, fl.TS)
	if err != nil {
		return model.IncidentReport{}, false, absorbError{err}
	}
	if persisted {
		return joined, false, nil
	}
	recentEvs, err := st.QueryEvents(store.EventFilter{Limit: 100})
	if err != nil {
		return model.IncidentReport{}, false, fmt.Errorf("incident recent events: %w", err)
	}
	report = i.analyzer.Analyze(fl, recentEvs)
	report.SessionID = fl.SessionID
	report.Subject = subject
	report.AggregateCount = 1
	if err := st.PutIncident(report); err != nil {
		return model.IncidentReport{}, false, fmt.Errorf("incident put: %w", err)
	}
	return report, true, nil
}
