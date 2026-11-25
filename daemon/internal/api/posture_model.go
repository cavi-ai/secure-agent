package api

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// postureInputs is a snapshot of the facts needed for one derivation. Storage
// and live-service reads happen at the boundary; ranking has no handler access.
type postureInputs struct {
	Status              Status
	Generated           time.Time
	Patterns            []model.Pattern
	Routine             []model.RoutineGroup
	Resources           []resource.Session
	HookGap             *PostureItem
	Pending             []guard.Pending
	Flags               []model.Flag
	Reviews             []model.ReviewRecord
	FlagReviews         map[string]model.ReviewRecord
	Incidents           []model.IncidentReport
	IncidentStates      map[string]string
	IncidentAssessments map[string]model.FindingAssessment
	FailedReads         []string
	HookFindings        []store.SessionHookFinding
	HookHealthTruncated bool
}

func derivePosture(in postureInputs) Posture {
	st := in.Status
	failedReads := in.FailedReads
	posture := Posture{
		Generated: in.Generated.UTC().Format(time.RFC3339Nano),
		Connected: st.Running,
	}
	queue := deriveAttention(in)
	posture.Items, posture.Groups = queue.Items, queue.Groups
	posture.NeedsYou = len(posture.Items)
	// Capture current health after all reads, including same-pass recovery.
	if len(failedReads) > 0 && st.StorageHealth != nil {
		h := *st.StorageHealth
		h.ReadActive = append(slices.Clone(h.ReadActive), failedReads...)
		slices.Sort(h.ReadActive)
		h.ReadActive = slices.Compact(h.ReadActive)
		st.StorageHealth = &h
	}
	posture.CoverageItems = coverageItems(in.Generated, st, in.HookGap)
	if in.HookHealthTruncated {
		posture.CoverageItems = append(posture.CoverageItems, PostureItem{Kind: "hook_analysis_limit", ID: "hook-analysis", MonitoringState: monitoringInformational, Title: "Hook analysis is limited to recent samples", Detail: "The latest 1,000 live-session completions and up to 20 repair findings are assessed. Open a session for its own assessment."})
	}
	for _, item := range posture.CoverageItems {
		if isMonitoringGap(item) {
			posture.CoverageCount++
		}
	}
	posture.AttentionSummary = deriveAttentionSummary(posture.Groups, posture.CoverageItems)
	switch {
	case posture.NeedsYou == 0 && !hasMonitoringGap(posture.CoverageItems):
		posture.State = "all-clear"
		posture.Summary = "No pending decisions. See finding history and incidents for remaining risk."
	case posture.NeedsYou == 0:
		posture.State = "attention"
		posture.Summary = "No decisions pending. Monitoring coverage needs attention."
	case hasCritical(posture.Items):
		posture.State = "critical"
		posture.Summary = criticalSummary(posture.Items)
	default:
		posture.State = "attention"
		posture.Summary = attentionSummary(posture.Items)
	}

	return posture
}

func coverageItems(now time.Time, st Status, hookGap *PostureItem) []PostureItem {
	items := machineAttentionItems(now, st, hookGap)
	if h := st.HookIngestion; h != nil {
		for _, row := range h.Forwarders {
			r := row.Report
			if row.Assessment.EvidenceGap {
				items = append(items, PostureItem{Kind: "hook_evidence_gap", ID: "hook-gap:" + r.ForwarderID, Title: familyTitle(r.Harness) + " hook evidence is incomplete", Detail: "The host reported dropped completions. Restored delivery cannot recover evidence that was discarded."})
			}
			if row.Assessment.State == "unknown" && r.State == "error" {
				items = append(items, PostureItem{Kind: "hook_delivery_unknown", ID: "hook-unknown:" + r.ForwarderID, Title: familyTitle(r.Harness) + " hook delivery error needs fresh evidence", Detail: "The previous error report is stale or unverified. Obtain a new host report; recovery has not been confirmed."})
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
		if isMonitoringGap(it) {
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

// humanPath shortens an absolute path to its tail for a headline.
func humanPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
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
