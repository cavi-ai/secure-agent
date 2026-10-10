package api

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// loadPostureInputs performs reads once, retaining failures before later reads
// can clear the store's active-read health. A review is resolved once per flag
// in this pass even when both a flag and an incident refer to it.
func (a *API) loadPostureInputs(st Status, patterns []model.Pattern, routine []model.RoutineGroup, failedReads []string) postureInputs {
	in := postureInputs{Status: st, Generated: time.Now(), Patterns: patterns, Routine: routine,
		FailedReads: failedReads}
	if a.resources != nil {
		in.Resources = a.resources().Sessions
	}
	if a.guardBroker != nil {
		in.Pending = a.guardBroker.Pending()
	}
	in = loadPostureEvidence(a.store, in)
	in.Status = a.evidenceStatus(st)
	in.HookGap = guardHookUnregisteredItem(in.Status)
	return in
}

func (a *API) attentionQueue(st Status, patterns []model.Pattern, routine []model.RoutineGroup) ([]PostureItem, []AttentionGroup) {
	queue := deriveAttention(a.loadPostureInputs(st, patterns, routine, nil))
	return queue.Items, queue.Groups
}
