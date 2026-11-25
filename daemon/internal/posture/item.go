// Package posture derives posture items from monitoring snapshots.
package posture

import "github.com/cavi-ai/secure-agent/daemon/internal/model"

// Monitoring classifications are derived by the daemon. Clients render these
// facts rather than treating every coverage observation as a current failure.
const (
	MonitoringActive        = "active"
	MonitoringHistorical    = "historical"
	MonitoringInformational = "informational"
	MonitoringDisabled      = "disabled"
)

// PostureItem is one thing the operator may need to act on.
type PostureItem struct {
	Kind       string                   `json:"kind"` // flag | incident | guard_pending | resource_pressure | coverage kinds
	ID         string                   `json:"id"`
	Title      string                   `json:"title"`
	Severity   int                      `json:"severity"` // 3 critical, 2 high, 1 medium, 0 info
	Detail     string                   `json:"detail,omitempty"`
	Timestamp  string                   `json:"ts,omitempty"`
	Assessment *model.FindingAssessment `json:"assessment,omitempty"`
	// MonitoringState separates an active fault from configuration and history.
	MonitoringState string `json:"monitoring_state,omitempty"`
}
