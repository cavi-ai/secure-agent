package posture

// FileTelemetryDisabled reports that configuration turned file telemetry off.
func FileTelemetryDisabled(st Status) bool {
	return st.FileTelemetryEnabled != nil && !*st.FileTelemetryEnabled
}

// FileTelemetryUnavailable reports that file telemetry is enabled but neither
// the root service nor an eslogger collector is present.
func FileTelemetryUnavailable(st Status) bool {
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
		item.MonitoringState = MonitoringActive
		switch item.Kind {
		case "uninspected_egress", "hook_analysis_limit", "harness_uncovered", "guard_hook_unregistered", "collector_idle":
			item.MonitoringState = MonitoringInformational
		case "collector_disabled":
			item.MonitoringState = MonitoringDisabled
		case "hook_evidence_gap", "file_evidence_loss":
			item.MonitoringState = MonitoringHistorical
		case "event_loss":
			if !st.BusDropping {
				item.MonitoringState = MonitoringHistorical
			}
		case "storage_loss":
			if st.StorageHealth != nil && len(st.StorageHealth.Active) == 0 {
				item.MonitoringState = MonitoringHistorical
			}
		case "projection_loss":
			if h := st.EgressProjectionHealth; h != nil && !h.WriteFailing && !h.QueueDropping {
				item.MonitoringState = MonitoringHistorical
			}
		case "export_loss":
			if !st.OTLPFailing {
				item.MonitoringState = MonitoringHistorical
			}
		}
		if item.MonitoringState != MonitoringActive {
			item.Severity = 0
		}
	}
	return items
}
