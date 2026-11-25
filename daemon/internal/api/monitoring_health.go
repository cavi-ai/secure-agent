package api

import "github.com/cavi-ai/secure-agent/daemon/internal/posture"

func fileTelemetryDisabled(st Status) bool {
	return st.FileTelemetryEnabled != nil && !*st.FileTelemetryEnabled
}

func fileTelemetryUnavailable(st Status) bool {
	if st.FileTelemetryEnabled == nil || !*st.FileTelemetryEnabled || st.ESService != nil {
		return false
	}
	for _, c := range st.Collectors {
		if c.Name == "eslogger" {
			return false
		}
	}
	return true
}

func classifyMonitoring(items []PostureItem, st Status) []PostureItem {
	for i := range items {
		item := &items[i]
		item.MonitoringState = posture.MonitoringActive
		switch item.Kind {
		case "uninspected_egress", "hook_analysis_limit", "harness_uncovered", "guard_hook_unregistered", "collector_idle":
			item.MonitoringState = posture.MonitoringInformational
		case "collector_disabled":
			item.MonitoringState = posture.MonitoringDisabled
		case "hook_evidence_gap", "file_evidence_loss":
			item.MonitoringState = posture.MonitoringHistorical
		case "event_loss":
			if !st.BusDropping {
				item.MonitoringState = posture.MonitoringHistorical
			}
		case "storage_loss":
			if st.StorageHealth != nil && len(st.StorageHealth.Active) == 0 {
				item.MonitoringState = posture.MonitoringHistorical
			}
		case "projection_loss":
			if h := st.EgressProjectionHealth; h != nil && !h.WriteFailing && !h.QueueDropping {
				item.MonitoringState = posture.MonitoringHistorical
			}
		case "export_loss":
			if !st.OTLPFailing {
				item.MonitoringState = posture.MonitoringHistorical
			}
		}
		if item.MonitoringState != posture.MonitoringActive {
			item.Severity = 0
		}
	}
	return items
}
