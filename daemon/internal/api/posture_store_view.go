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
	QueryFlags(store.FlagFilter) ([]model.Flag, error)
	GetFlag(string) (model.Flag, bool, error)
	RecentIncidentDetails(int) ([]store.IncidentDetail, error)
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
	in.IncidentAssessments = map[string]model.FindingAssessment{}
	reviews := newFindingReviewView(st)
	page, reviewErr := reviews.Unreviewed()
	if reviewErr != nil {
		in.FailedReads = append(in.FailedReads, "finding reviews")
	} else {
		in.Reviews = page.Reviews
	}
	flags, err := st.QueryFlags(store.FlagFilter{MinSeverity: 3, Limit: 25, Unacted: true})
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
	incidents, err := st.RecentIncidentDetails(25)
	in.Incidents = nil
	in.FailedReads = append(in.FailedReads, advisorReadFailuresFrom(st, "incident")...)
	if err != nil {
		in.FailedReads = append(in.FailedReads, "incidents")
	}
	for _, inc := range incidents {
		in.Incidents = append(in.Incidents, inc.IncidentReport)
		if inc.Rule == "untrusted-egress" {
			f, found, err := st.GetFlag(inc.FlagID)
			if err != nil {
				in.FailedReads = append(in.FailedReads, "incident flag evidence")
			} else if found && f.Rule == inc.Rule {
				in.IncidentAssessments[inc.FlagID] = model.AssessFinding(f)
			}
		}
		lookup(inc.FlagID)
		if r, ok := in.FlagReviews[inc.FlagID]; ok && r.Context.Attribution == "stored-session" {
			continue
		}
		in.IncidentStates[inc.ID] = inc.Workflow.Status
	}
	return in
}
