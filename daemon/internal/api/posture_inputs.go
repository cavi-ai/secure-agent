package api

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

// loadPostureInputs performs reads once, retaining failures before later reads
// can clear the store's active-read health. A review is resolved once per flag
// in this pass even when both a flag and an incident refer to it.
func (a *API) loadPostureInputs(st Status, patterns []model.Pattern, routine []model.RoutineGroup, failedReads []string) posture.Inputs {
	in := posture.Inputs{Status: posture.Status(st), Generated: time.Now(), Patterns: patterns, Routine: routine,
		FailedReads: failedReads}
	if a.resources != nil {
		in.Resources = a.resources().Sessions
	}
	if a.guardBroker != nil {
		in.Pending = a.guardBroker.Pending()
	}
	in = loadPostureEvidence(a.store, in)
	var hookErr error
	in.HookFindings, in.HookHealthTruncated, hookErr = a.store.ActiveHookFindings(in.Generated)
	if hookErr != nil {
		in.FailedReads = append(in.FailedReads, "hook health")
	}
	in.Status = posture.Status(a.evidenceStatus(st))
	in.HookGap = guardHookUnregisteredItem(Status(in.Status))
	return in
}

func (a *API) attentionQueue(st Status, patterns []model.Pattern, routine []model.RoutineGroup) ([]PostureItem, []AttentionGroup) {
	queue := posture.DeriveAttention(a.loadPostureInputs(st, patterns, routine, nil), dispositionFor)
	return queue.Items, queue.Groups
}
