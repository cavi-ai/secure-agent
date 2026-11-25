package api

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func derivePosture(in posture.Inputs) Posture {
	st := Status(in.Status)
	failedReads := in.FailedReads
	p := Posture{
		Generated: in.Generated.UTC().Format(time.RFC3339Nano),
		Connected: st.Running,
	}
	queue := posture.DeriveAttention(in, dispositionFor)
	p.Items, p.Groups = queue.Items, queue.Groups
	p.NeedsYou = len(p.Items)
	// Capture current health after all reads, including same-pass recovery.
	if len(failedReads) > 0 && st.StorageHealth != nil {
		h := *st.StorageHealth
		h.ReadActive = append(slices.Clone(h.ReadActive), failedReads...)
		slices.Sort(h.ReadActive)
		h.ReadActive = slices.Compact(h.ReadActive)
		st.StorageHealth = &h
	}
	p.CoverageItems = coverageItems(in.Generated, st, in.HookGap)
	if in.HookHealthTruncated {
		p.CoverageItems = append(p.CoverageItems, PostureItem{Kind: "hook_analysis_limit", ID: "hook-analysis", MonitoringState: posture.MonitoringInformational, Title: "Hook analysis is limited to recent samples", Detail: "The latest 1,000 live-session completions and up to 20 repair findings are assessed. Open a session for its own assessment."})
	}
	for _, item := range p.CoverageItems {
		if posture.IsMonitoringGap(item) {
			p.CoverageCount++
		}
	}
	p.AttentionSummary = posture.DeriveAttentionSummary(p.Groups, p.CoverageItems)
	switch {
	case p.NeedsYou == 0 && !hasMonitoringGap(p.CoverageItems):
		p.State = "all-clear"
		p.Summary = "No pending decisions. See finding history and incidents for remaining risk."
	case p.NeedsYou == 0:
		p.State = "attention"
		p.Summary = "No decisions pending. Monitoring coverage needs attention."
	case hasCritical(p.Items):
		p.State = "critical"
		p.Summary = criticalSummary(p.Items)
	default:
		p.State = "attention"
		p.Summary = attentionSummary(p.Items)
	}

	return p
}

// machineGroupKey is retained for the machine-level coverage section.
const machineGroupKey = "machine"

// machineAttentionItems are the signals no agent owns: dead collectors, and
// while agents are active, silent collectors and missing hooks.
func machineAttentionItems(now time.Time, st Status, hookGap *PostureItem) []PostureItem {
	var items []PostureItem
	if fileTelemetryDisabled(st) {
		items = append(items, PostureItem{Kind: "collector_disabled", ID: "eslogger", Title: "File monitoring is off", Detail: "File telemetry is disabled in configuration."})
	} else if fileTelemetryUnavailable(st) {
		items = append(items, PostureItem{Kind: "collector_down", ID: "eslogger", Severity: 2, Title: "File monitoring is unavailable", Detail: "File telemetry is enabled but no file collector is available. Check Setup & Permissions in the menu bar."})
	}
	if h := st.EgressProjectionHealth; h != nil && (h.QueueDrops > 0 || h.WriteFailures > 0) {
		detail := fmt.Sprintf("%d observations missed the summary queue; %d summary writes failed since daemon start. Recurring egress summaries may be incomplete. Connection evidence has separate storage health.", h.QueueDrops, h.WriteFailures)
		if h.WriteFailing {
			detail += " Summary writes are still failing."
		} else if h.WriteFailures > 0 {
			detail += " New summary writes have recovered."
		}
		items = append(items, PostureItem{Kind: "projection_loss", ID: "egress", Severity: 2, Title: "Recurring egress summary missed activity", Detail: detail})
	}
	if st.OTLPDropped > 0 {
		items = append(items, PostureItem{Kind: "export_loss", ID: "otlp", Severity: 2, Title: "Trace export lost spans", Detail: fmt.Sprintf("%d spans could not be exported since daemon start. Local evidence is retained separately.", st.OTLPDropped)})
	}
	if st.BusDropping || st.BusDrops > 0 {
		items = append(items, PostureItem{Kind: "event_loss", ID: "event-bus", Severity: 2,
			Title:  "Telemetry was dropped",
			Detail: fmt.Sprintf("%d subscriber deliveries dropped since daemon start. Monitoring history may be incomplete.", st.BusDrops)})
	}
	if s := st.ESService; s != nil && s.BytesLost > 0 && (!s.Losing || fileTelemetryDisabled(st)) {
		items = append(items, PostureItem{Kind: "file_evidence_loss", ID: "es-history", Title: "Earlier file monitoring evidence was lost", Detail: posture.ESLossDetail(*s)})
	}
	if h := st.StorageHealth; h != nil && len(h.ReadActive) > 0 {
		items = append(items, PostureItem{Kind: "storage_read_failure", ID: "storage-reads", Severity: 2, Title: "Evidence could not be read", Detail: "Last known activity may be stale. Reads failing: " + strings.Join(h.ReadActive, ", ") + "." + readIssueDetail(*h)})
	}
	if h := st.StorageHealth; h != nil && h.Failures > 0 {
		detail := fmt.Sprintf("%d evidence persistence attempts failed since daemon start. Monitoring history may be incomplete.", h.Failures)
		if len(h.Active) > 0 {
			detail += " Writes still failing: " + strings.Join(h.Active, ", ") + "."
		} else {
			detail += " New writes have recovered; earlier evidence may remain incomplete."
		}
		items = append(items, PostureItem{Kind: "storage_loss", ID: "storage", Severity: 2,
			Title: "Evidence could not be saved", Detail: detail})
	}
	// A monitor that stopped is a blind spot, not a detail.
	for _, c := range st.Collectors {
		if c.Name == "eslogger" && fileTelemetryDisabled(st) {
			continue
		}
		if !c.Running || c.Abandoned {
			items = append(items, PostureItem{
				Kind: "collector_down", ID: c.Name,
				Title:    humanCollectorTitle(c.Name, c.Abandoned),
				Severity: 2,
				Detail:   humanCollectorDetail(c.Name, c.LastError),
			})
		}
	}
	// Liveness is not coverage: the worst failure mode a monitor can have is
	// reporting green while blind (both audited live: the eslogger spool
	// untouched for days, zero hook events for 17h, all "healthy").
	if st.ActiveAgents > 0 {
		items = append(items, silentCollectorItems(now, st)...)
		if st.Coverage != nil {
			items = append(items, harnessUncoveredItems(st.Coverage.Harnesses)...)
		}
		if hookGap != nil {
			items = append(items, *hookGap)
		}
	}
	return items
}

// readIssueDetail adds the newest safe diagnostic for an active operation.
// The complete per-operation history remains available in storage_health.
func readIssueDetail(h store.WriteHealth) string {
	var latest *store.ReadIssue
	for i := range h.ReadIssues {
		issue := &h.ReadIssues[i]
		if issue.RecoveredAt != nil {
			continue
		}
		if latest == nil || issue.LastFailureAt.After(latest.LastFailureAt) {
			latest = issue
		}
	}
	if latest == nil {
		return ""
	}
	return " Last read failure: " + latest.Operation + " (" + latest.Category + ") at " + latest.LastFailureAt.UTC().Format(time.RFC3339) + "."
}

func coverageItems(now time.Time, st Status, hookGap *PostureItem) []PostureItem {
	items := machineAttentionItems(now, st, hookGap)
	if h := st.HookIngestion; h != nil {
		for _, row := range h.Forwarders {
			r := row.Report
			if row.Assessment.EvidenceGap {
				items = append(items, PostureItem{Kind: "hook_evidence_gap", ID: "hook-gap:" + r.ForwarderID, Title: posture.FamilyTitle(r.Harness) + " hook evidence is incomplete", Detail: "The host reported dropped completions. Restored delivery cannot recover evidence that was discarded."})
			}
			if row.Assessment.State == "unknown" && r.State == "error" {
				items = append(items, PostureItem{Kind: "hook_delivery_unknown", ID: "hook-unknown:" + r.ForwarderID, Title: posture.FamilyTitle(r.Harness) + " hook delivery error needs fresh evidence", Detail: "The previous error report is stale or unverified. Obtain a new host report; recovery has not been confirmed."})
			}
		}
	}
	if st.UninspectedEgress > 0 {
		items = append(items, PostureItem{
			Kind: "uninspected_egress", ID: "uninspected-egress",
			Title:    uninspectedTitle(st.UninspectedEgress),
			Severity: 1,
			Detail:   "Review endpoints that bypassed inspection in Egress.",
		})
	}
	return classifyMonitoring(items, st)
}

// hasMonitoringGap reports current failures. Configuration notes, idle
// sources and historical losses remain inspectable without requiring attention.
func hasMonitoringGap(items []PostureItem) bool {
	for _, it := range items {
		if posture.IsMonitoringGap(it) {
			return true
		}
	}
	return false
}

func hasCritical(items []PostureItem) bool {
	for _, it := range items {
		if it.Severity >= 3 {
			return true
		}
	}
	return false
}

func firstNonEmpty(strs []string) string {
	for _, s := range strs {
		if s != "" {
			return s
		}
	}
	return ""
}

// criticalSummary picks the highest-severity item as the one-line headline.
func criticalSummary(items []PostureItem) string {
	for _, it := range items {
		if it.Severity >= 3 {
			if it.Assessment != nil && it.Assessment.Reason != "" {
				return it.Assessment.Reason
			}
			if it.Kind == "incident" {
				return it.Title + " — review the incident report."
			}
			return it.Title + " — review the recorded evidence."
		}
	}
	return attentionSummary(items)
}

// attentionSummary names the count and the most severe non-critical item.
func attentionSummary(items []PostureItem) string {
	top := items[0]
	for _, it := range items[1:] {
		if it.Severity > top.Severity {
			top = it
		}
	}
	n := len(items)
	noun := "items need"
	if n == 1 {
		noun = "item needs"
	}
	return fmt.Sprintf("%d %s you — first: %s.", n, noun, top.Title)
}

// collectorSilenceWindows: how long a producer collector may publish nothing
// while agents are active before posture calls it blind. Netsampler is
// excluded. A quiet source is an observation, not evidence of a failure:
// long-lived processes and helpers can remain present without doing work.
var collectorSilenceWindows = map[string]time.Duration{
	"eslogger":   30 * time.Minute,
	"transcript": 30 * time.Minute,
}

// collectorBootGrace suppresses never-produced items right after daemon
// start: collectors need a few minutes to see their first event.
const collectorBootGrace = 10 * time.Minute

// silentCollectorItems flags running collectors that have produced nothing
// recent (or nothing at all past the boot grace) while agents are active.
// For the eslogger tailer the goroutine's heartbeat is not the whole story:
// the WRITER is the root LaunchDaemon, so its real launchd state and spool
// freshness are probed too — a crash-looping writer (exit 1 every respawn)
// must read as blind even while the tailer itself runs green.
func silentCollectorItems(now time.Time, st Status) []PostureItem {
	var items []PostureItem
	uptime, _ := time.ParseDuration(st.Uptime)
	// Probe the root service once per posture pass; only meaningful when
	// the daemon tails the spool (an eslogger collector row that came from
	// a direct root eslogger child has no external service).
	for _, c := range st.Collectors {
		if c.Name == "eslogger" && fileTelemetryDisabled(st) {
			continue
		}
		if c.Name == "eslogger" && c.Running && !c.Abandoned && st.ESService != nil {
			svcItems := posture.ESServiceItems(now, *st.ESService)
			items = append(items, svcItems...)
			// The spool-based probe supersedes the tailer heartbeat when it
			// reports a failure: both would emit collector_silent under the
			// same id, double-counting one blind spot. A healthy probe with
			// a still-silent tailer keeps the generic check.
			if len(svcItems) > 0 {
				continue
			}
		}
		if !c.Running || c.Abandoned {
			continue
		}
		window, watched := collectorSilenceWindows[c.Name]
		if !watched {
			continue
		}
		if c.LastProduced == "" {
			if uptime >= collectorBootGrace {
				items = append(items, PostureItem{
					Kind: "collector_idle", ID: c.Name,
					Title:  humanCollectorSilentTitle(c.Name) + ": no activity observed",
					Detail: "The collector is running. No events have been observed during this run.",
				})
			}
			continue
		}
		last, err := time.Parse(time.RFC3339, c.LastProduced)
		if err != nil {
			continue
		}
		if now.Sub(last) > window {
			items = append(items, PostureItem{
				Kind: "collector_idle", ID: c.Name,
				Title:  humanCollectorSilentTitle(c.Name) + ": no recent activity",
				Detail: "The collector is running. Its last event was over " + window.String() + " ago.",
			})
		}
	}
	return items
}

func humanCollectorSilentTitle(name string) string {
	switch name {
	case "eslogger":
		return "File monitoring"
	case "transcript":
		return "Transcript scanning"
	}
	return "Monitor " + name
}

// hookActivityWindow is how far back hook evidence counts as activity.
const hookActivityWindow = 24 * time.Hour
