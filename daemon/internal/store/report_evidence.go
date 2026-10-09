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

func (e ReportEvidence) Partial() bool {
	for _, source := range []ReportSourceEvidence{e.Events, e.Flags, e.Reviews, e.Incidents, e.Interventions} {
		if !source.Available || source.AtLimit {
			return true
		}
	}
	return false
}
