package hookhealth

import "github.com/cavi-ai/secure-agent/daemon/hookrun"

// DeliveryAssessment is shared by status, Attention and session diagnostics.
// It describes observed delivery, never hook execution or protection coverage.
type DeliveryAssessment struct {
	State       string          `json:"state"`
	Title       string          `json:"title"`
	Issues      []DeliveryIssue `json:"issues"`
	EvidenceGap bool            `json:"evidence_gap"`
	Limits      []string        `json:"limits"`
}

type DeliveryIssue struct {
	Stage      string `json:"stage"`
	Code       string `json:"code"`
	NextAction string `json:"next_action"`
}

func AssessDelivery(r hookrun.ForwarderReport, freshness string) DeliveryAssessment {
	a := DeliveryAssessment{State: "unknown", Title: "Hook delivery state unknown", Issues: []DeliveryIssue{},
		Limits: []string{"Host reports do not establish complete delivery or protection coverage."}}
	if r.Validate() != nil {
		return a
	}
	a.EvidenceGap = r.Dropped > 0
	if freshness != "recent" {
		a.Limits = append(a.Limits, "A fresh valid host report is required; absence of an active finding does not confirm recovery.")
		return a
	}
	a.State, a.Title = "no-active-error", "No active hook delivery error reported"
	add := func(stage, code, action string) {
		a.Issues = append(a.Issues, DeliveryIssue{Stage: stage, Code: code, NextAction: action})
	}
	if r.Health == nil {
		a.Limits = append(a.Limits, "This legacy report does not distinguish source, capture, delivery or persistence errors.")
		if r.State == "error" {
			add("forwarding", "legacy-error", "Check the reporting host and recorder diagnostics, then obtain a new report.")
		}
	} else {
		h := r.Health
		if h.SourceState == "error" {
			add("source", "source-error", "Check the host's hook-source subscription and obtain a new source observation.")
		}
		for _, item := range []struct {
			stage string
			code  hookrun.FailureCode
		}{{"capture", h.CaptureError}, {"delivery", h.DeliveryError}} {
			if item.code != "" {
				add(item.stage, string(item.code), deliveryAction(item.code))
			}
		}
		if h.Outbox != nil && h.Outbox.Error != "" {
			add("persistence", string(h.Outbox.Error), deliveryAction(h.Outbox.Error))
		}
	}
	if len(a.Issues) > 0 {
		a.State, a.Title = "needs-action", "Hook delivery needs attention"
	}
	return a
}

func deliveryAction(code hookrun.FailureCode) string {
	switch code {
	case hookrun.ErrInvalidInput:
		return "Validate the completion metadata against the shared contract, then submit the corrected completion."
	case hookrun.ErrUnsupportedProtocol:
		return "Use the supported native hook protocol and required snapshots, then submit the corrected completion."
	case hookrun.ErrScopeMismatch:
		return "Route the completion to the forwarder for its harness and session."
	case hookrun.ErrDeliveryConflict:
		return "Keep one execution ID for identical retry metadata; use a new ID for a different execution."
	case hookrun.ErrQueueFull:
		return "Restore delivery and allow the queue to drain. Some rejected completions may be unrecoverable."
	case hookrun.ErrRecorderUnavailable:
		return "Restore the installed recorder executable and its permissions. Retry retained completions using their original delivery IDs."
	case hookrun.ErrRecorderFailed:
		return "Check the recorder and its output storage. Retry retained completions using their original delivery IDs."
	case hookrun.ErrOutboxFull:
		return "Free outbox storage or increase its configured budget. Keep the existing outbox to preserve pending evidence."
	default:
		return "Check outbox storage availability and permissions. Keep the existing outbox to preserve pending evidence."
	}
}
