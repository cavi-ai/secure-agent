package api

// Monitoring classifications are derived by the daemon. Clients render these
// facts rather than treating every coverage observation as a current failure.
const (
	monitoringActive        = "active"
	monitoringHistorical    = "historical"
	monitoringInformational = "informational"
	monitoringDisabled      = "disabled"
)

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
		item.MonitoringState = monitoringActive
		switch item.Kind {
		case "uninspected_egress", "hook_analysis_limit", "harness_uncovered", "guard_hook_unregistered", "collector_idle":
			item.MonitoringState = monitoringInformational
		case "collector_disabled":
			item.MonitoringState = monitoringDisabled
		case "hook_evidence_gap", "file_evidence_loss":
			item.MonitoringState = monitoringHistorical
		case "event_loss":
			if !st.BusDropping {
				item.MonitoringState = monitoringHistorical
			}
		case "storage_loss":
			if st.StorageHealth != nil && len(st.StorageHealth.Active) == 0 {
				item.MonitoringState = monitoringHistorical
			}
		case "projection_loss":
			if h := st.EgressProjectionHealth; h != nil && !h.WriteFailing && !h.QueueDropping {
				item.MonitoringState = monitoringHistorical
			}
		case "export_loss":
			if !st.OTLPFailing {
				item.MonitoringState = monitoringHistorical
			}
		}
		if item.MonitoringState != monitoringActive {
			item.Severity = 0
		}
	}
	return items
}
