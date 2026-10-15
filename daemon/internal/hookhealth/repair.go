package hookhealth

import (
	"sort"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

// RepairVerification describes subsequent observations, never proof of repair
// or protection. Callers scope runs to one session, harness, event and handler.
type RepairVerification struct {
	State      string     `json:"state"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	RunIDs     []string   `json:"run_ids"`
	ConfigID   string     `json:"config_id"`
	ReasonCode string     `json:"reason_code,omitempty"`
	Truncated  bool       `json:"truncated"`
	Limits     []string   `json:"limits"`
}

func VerifyRepair(runs []hookrun.Record, config, script string, after, now time.Time, truncated bool) RepairVerification {
	v := RepairVerification{State: "unconfirmed", Title: "Repair unconfirmed", Detail: "The original failure is not available in the retained evidence.", RunIDs: []string{}, Truncated: truncated,
		Limits: []string{"Recorded completions do not establish complete delivery, lasting repair or protection coverage."}}
	if config == "" {
		v.Limits = append(v.Limits, "The original configuration revision was not supplied; an unchanged configuration cannot be confirmed.")
	}
	if after.IsZero() || after.Before(now.Add(-Window)) || after.After(now) {
		v.Detail = "The original failure is outside the current evidence window."
		return v
	}
	if truncated {
		v.Detail = "The retained sample is limited. Verification requires an untruncated sample."
		return v
	}
	found, ambiguousBaseline := false, false
	var latest time.Time
	var bucket []hookrun.Record
	for _, r := range runs {
		if r.TS.Before(now.Add(-Window)) || r.TS.After(now) || r.Evidence == nil {
			continue
		}
		if r.TS.Equal(after) {
			found = found || r.Status == "error" && r.Evidence.ConfigID == config && r.Script == script
			ambiguousBaseline = ambiguousBaseline || r.Status != "error" || r.Evidence.ConfigID != config
		}
		if !r.TS.After(after) {
			continue
		}
		if r.TS.After(latest) {
			latest, bucket = r.TS, nil
		}
		if r.TS.Equal(latest) {
			bucket = append(bucket, r)
		}
	}
	if !found {
		return v
	}
	if ambiguousBaseline {
		v.Detail = "Other outcomes share the original failure timestamp; execution order is unknown."
		return v
	}
	if len(bucket) == 0 {
		v.State, v.Title, v.Detail = "awaiting-completion", "Waiting for a newer completion", "No newer retained completion for this handler and event has been observed. Use the hook normally, then check again."
		return v
	}
	v.ObservedAt = &latest
	v.ConfigID = bucket[0].Evidence.ConfigID
	v.ReasonCode = bucket[0].Evidence.ReasonCode
	statusClass := func(s string) string {
		switch s {
		case "ok", "inject":
			return "successful-completion"
		case "block", "deny":
			return "decision-observed"
		case "error":
			return "still-failing"
		default:
			return "unconfirmed"
		}
	}
	class, mixed := statusClass(bucket[0].Status), false
	for _, r := range bucket {
		v.RunIDs = append(v.RunIDs, r.ID)
		mixed = mixed || r.Evidence.ConfigID != v.ConfigID || statusClass(r.Status) != class
		if r.Evidence.ReasonCode != v.ReasonCode {
			v.ReasonCode = ""
		}
	}
	sort.Strings(v.RunIDs) // Stable display only; IDs never establish chronology.
	if mixed {
		v.ConfigID, v.ReasonCode = "", ""
		v.Detail = "Different outcomes or configurations share the newest timestamp; execution order is unknown."
		return v
	}
	if v.ConfigID != config {
		if v.ConfigID == "" {
			v.Detail = "The newer completion omits its configuration revision; it cannot verify the original configuration."
			return v
		}
		v.State, v.Title, v.Detail = "configuration-changed", "Configuration changed", "A different configuration has newer recorded completions. Assess it separately; this does not confirm repair of the original configuration."
		return v
	}
	v.State = class
	switch class {
	case "successful-completion":
		v.Title, v.Detail = "Successful completion observed", "The newest recorded completion for this handler and event succeeded after the original failure. This observation does not confirm lasting repair."
	case "still-failing":
		v.Title, v.Detail = "Still failing", "The newest recorded completion for this handler and event is an execution error. Review its reported reason and local diagnostics."
	case "decision-observed":
		v.Title, v.Detail = "Block decision observed; repair unconfirmed", "The newer callback returned a block decision. It may be expected behavior; the original repair and protection coverage remain unconfirmed."
	default:
		v.Title, v.Detail = "Completion cancelled; repair unconfirmed", "The newer callback was cancelled. Cancellation does not verify the original repair."
	}
	return v
}
