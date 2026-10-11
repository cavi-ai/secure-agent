package api

import (
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type advisorReadHealthStore interface {
	WriteHealth() store.WriteHealth
}

// postureEvidenceStore supplies retained evidence for one posture calculation.
// Live status, resource controls, and pending prompts are separate inputs.
type postureEvidenceStore interface {
	findingReviewStore
	advisorReadHealthStore
	QueryFlagsResult(store.FlagFilter) ([]model.Flag, error)
	RecentIncidentsResult(int) ([]model.IncidentReport, error)
	IncidentStatusResult(string) (store.IncidentWorkflow, bool, error)
}

func advisorReadFailuresFrom(st advisorReadHealthStore, kind string) []string {
	label := kind + " advisor verdicts"
	if slices.Contains(st.WriteHealth().ReadActive, label) {
		return []string{label}
	}
	return nil
}

// loadPostureEvidence preserves same-pass failures before subsequent reads can
// clear their health. The snapshot clock governs the flag freshness cutoff.
func loadPostureEvidence(st postureEvidenceStore, in postureInputs) postureInputs {
	in.FailedReads = slices.Clone(in.FailedReads)
	in.FlagReviews = map[string]model.ReviewRecord{}
	in.IncidentStates = map[string]string{}
	reviews := newFindingReviewView(st)
	page, reviewErr := reviews.Unreviewed()
	if reviewErr != nil {
		in.FailedReads = append(in.FailedReads, "finding reviews")
	} else {
		in.Reviews = page.Reviews
	}
	flags, err := st.QueryFlagsResult(store.FlagFilter{MinSeverity: 3, Limit: 25, Unacted: true})
	in.Flags = nil
	if err == nil {
		for _, f := range flags {
			if !f.TS.IsZero() && in.Generated.Sub(f.TS) <= 24*time.Hour {
				in.Flags = append(in.Flags, f)
			}
		}
	}
	in.FailedReads = append(in.FailedReads, advisorReadFailuresFrom(st, "flag")...)
	if err != nil {
		in.FailedReads = append(in.FailedReads, "flags")
	}
	lookup := func(flagID string) {
		if reviewErr != nil {
			return
		}
		r, ok, err := reviews.ForFlag(flagID)
		if err != nil {
			in.FailedReads = append(in.FailedReads, "finding reviews")
		} else if ok {
			in.FlagReviews[flagID] = r
		}
	}
	for _, f := range in.Flags {
		if f.Rule == readConnectRule {
			lookup(f.ID)
		}
	}
	incidents, err := st.RecentIncidentsResult(25)
	in.Incidents = incidents
	in.FailedReads = append(in.FailedReads, advisorReadFailuresFrom(st, "incident")...)
	if err != nil {
		in.FailedReads = append(in.FailedReads, "incidents")
	}
	for _, inc := range incidents {
		lookup(inc.FlagID)
		if r, ok := in.FlagReviews[inc.FlagID]; ok && r.Context.Attribution == "stored-session" {
			continue
		}
		wf, found, err := st.IncidentStatusResult(inc.ID)
		if err != nil || !found {
			in.FailedReads = append(in.FailedReads, "incident workflows")
			continue
		}
		in.IncidentStates[inc.ID] = wf.Status
	}
	return in
}
