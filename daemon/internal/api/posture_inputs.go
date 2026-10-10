package api

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// attentionFlags is the one flag query behind the queue: unacknowledged
// flags of severity 3 (critical) raised in the last 24h.
func (a *API) attentionFlags() []model.Flag {
	flags, _ := a.attentionFlagsResult()
	return flags
}

func (a *API) attentionFlagsResult() ([]model.Flag, error) {
	flags, err := a.store.QueryFlagsResult(store.FlagFilter{MinSeverity: 3, Limit: 25, Unacted: true})
	if err != nil {
		return nil, err
	}
	var out []model.Flag
	for _, f := range flags {
		if isRecent(f.TS, 24*time.Hour) {
			out = append(out, f)
		}
	}
	return out, nil
}

// loadPostureInputs performs reads once, retaining failures before later reads
// can clear the store's active-read health. A review is resolved once per flag
// in this pass even when both a flag and an incident refer to it.
func (a *API) loadPostureInputs(st Status, patterns []model.Pattern, routine []model.RoutineGroup, failedReads []string) postureInputs {
	in := postureInputs{Status: st, Generated: time.Now(), Patterns: patterns, Routine: routine,
		FailedReads: append([]string(nil), failedReads...), FlagReviews: map[string]model.ReviewRecord{}, IncidentStates: map[string]string{}}
	if a.resources != nil {
		in.Resources = a.resources().Sessions
	}
	if a.guardBroker != nil {
		in.Pending = a.guardBroker.Pending()
	}
	reviews := newFindingReviewView(a.store)
	page, reviewErr := reviews.Unreviewed()
	if reviewErr != nil {
		in.FailedReads = append(in.FailedReads, "finding reviews")
	} else {
		in.Reviews = page.Reviews
	}
	flags, err := a.attentionFlagsResult()
	in.Flags = flags
	in.FailedReads = append(in.FailedReads, a.advisorReadFailures("flag")...)
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
	for _, f := range flags {
		if f.Rule == readConnectRule {
			lookup(f.ID)
		}
	}
	incidents, err := a.store.RecentIncidentsResult(25)
	in.Incidents = incidents
	in.FailedReads = append(in.FailedReads, a.advisorReadFailures("incident")...)
	if err != nil {
		in.FailedReads = append(in.FailedReads, "incidents")
	}
	for _, inc := range incidents {
		lookup(inc.FlagID)
		if r, ok := in.FlagReviews[inc.FlagID]; ok && r.Context.Attribution == "stored-session" {
			continue
		}
		wf, found, err := a.store.IncidentStatusResult(inc.ID)
		if err != nil || !found {
			in.FailedReads = append(in.FailedReads, "incident workflows")
			continue
		}
		in.IncidentStates[inc.ID] = wf.Status
	}
	in.Status = a.evidenceStatus(st)
	in.HookGap = guardHookUnregisteredItem(in.Status)
	return in
}

func (a *API) attentionQueue(st Status, patterns []model.Pattern, routine []model.RoutineGroup) ([]PostureItem, []AttentionGroup) {
	queue := deriveAttention(a.loadPostureInputs(st, patterns, routine, nil))
	return queue.Items, queue.Groups
}

func isRecent(ts time.Time, window time.Duration) bool {
	if ts.IsZero() {
		return false
	}
	return time.Since(ts) <= window
}
