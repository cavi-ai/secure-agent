package store

// ReportSourceEvidence describes the retained rows read for an export.
// AtLimit means additional history may be omitted, not that it exists.
type ReportSourceEvidence struct {
	Available bool `json:"available"`
	AtLimit   bool `json:"at_limit"`
	Limit     int  `json:"limit"`
}

type ReportEvidence struct {
	Events        ReportSourceEvidence `json:"events"`
	Flags         ReportSourceEvidence `json:"flags"`
	Reviews       ReportSourceEvidence `json:"reviews"`
	Incidents     ReportSourceEvidence `json:"incidents"`
	Interventions ReportSourceEvidence `json:"interventions"`
}

// Partial is the export signal: any source is unavailable or at its limit.
func (e ReportEvidence) Partial() bool {
	for _, source := range []ReportSourceEvidence{e.Events, e.Flags, e.Reviews, e.Incidents, e.Interventions} {
		if !source.Available || source.AtLimit {
			return true
		}
	}
	return false
}

// PlanCoreUnavailable is the plan rule. It is true when events or flags
// are unavailable. AtLimit and reviews, incidents, and interventions do
// not trip it. A nil ReportEvidence does not.
func (e *ReportEvidence) PlanCoreUnavailable() bool {
	if e == nil {
		return false
	}
	return !e.Events.Available || !e.Flags.Available
}
