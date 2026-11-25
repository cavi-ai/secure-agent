package api

import (
	"maps"
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

// loadPostureInputs performs reads once, retaining failures before later reads
// can clear the store's active-read health. A review is resolved once per flag
// in this pass even when both a flag and an incident refer to it.
func (a *API) loadPostureInputs(st Status, patterns []model.Pattern, routine []model.RoutineGroup, failedReads []string) posture.Inputs {
	now := a.clock()
	return a.postureInputsFrom(st, now, patterns, routine, failedReads, a.readPostureEvidence(now))
}

// readPostureEvidence performs the store reads of one posture calculation at
// now; FailedReads lists only the failures these reads met.
func (a *API) readPostureEvidence(now time.Time) posture.Inputs {
	in := loadPostureEvidence(a.store, posture.Inputs{Generated: now})
	var hookErr error
	in.HookFindings, in.HookHealthTruncated, hookErr = a.store.ActiveHookFindings(now)
	if hookErr != nil {
		in.FailedReads = append(in.FailedReads, "hook health")
	}
	return in
}

// postureInputsFrom joins evidence read earlier with live status, resource
// controls and pending prompts. It copies evidence slices and maps.
func (a *API) postureInputsFrom(st Status, now time.Time, patterns []model.Pattern, routine []model.RoutineGroup, failedReads []string, ev posture.Inputs) posture.Inputs {
	in := ev
	in.Generated, in.Patterns, in.Routine = now, patterns, routine
	in.FailedReads = append(slices.Clone(failedReads), ev.FailedReads...)
	in.Reviews, in.Flags, in.Incidents = slices.Clone(ev.Reviews), slices.Clone(ev.Flags), slices.Clone(ev.Incidents)
	in.HookFindings = slices.Clone(ev.HookFindings)
	in.FlagReviews, in.IncidentStates = maps.Clone(ev.FlagReviews), maps.Clone(ev.IncidentStates)
	in.IncidentAssessments = maps.Clone(ev.IncidentAssessments)
	if a.resources != nil {
		in.Resources = a.resources().Sessions
	}
	if a.guardBroker != nil {
		in.Pending = a.guardBroker.Pending()
	}
	in.Status = posture.Status(a.evidenceStatus(st))
	in.HookGap = guardHookUnregisteredItem(Status(in.Status))
	return in
}

func (a *API) attentionQueue(st Status, patterns []model.Pattern, routine []model.RoutineGroup) ([]PostureItem, []AttentionGroup) {
	queue := posture.DeriveAttention(a.loadPostureInputs(st, patterns, routine, nil), dispositionFor)
	return queue.Items, queue.Groups
}
