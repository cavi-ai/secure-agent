package api

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

// postureInputs is a snapshot of the facts needed for one derivation. Storage
// and live-service reads happen at the boundary; ranking has no handler access.
type postureInputs struct {
	Status         Status
	Generated      time.Time
	Patterns       []model.Pattern
	Routine        []model.RoutineGroup
	Resources      []resource.Session
	HookGap        *PostureItem
	Pending        []guard.Pending
	Flags          []model.Flag
	Reviews        []model.ReviewRecord
	FlagReviews    map[string]model.ReviewRecord
	Incidents      []model.IncidentReport
	IncidentStates map[string]string
	FailedReads    []string
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
	posture.CoverageCount = len(posture.CoverageItems)
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
	if st.UninspectedEgress > 0 {
		items = append(items, PostureItem{
			Kind: "uninspected_egress", ID: "uninspected-egress",
			Title:    uninspectedTitle(st.UninspectedEgress),
			Severity: 1,
			Detail:   "Review endpoints that bypassed inspection in Egress.",
		})
	}
	return items
}

// hasMonitoringGap reports whether coverage holds a gap the operator must fix
// (a collector down or silent, a hook missing, a harness unseen). Uninspected
// egress is a coverage note, not a gap: alone it leaves posture all-clear.
func hasMonitoringGap(items []PostureItem) bool {
	for _, it := range items {
		if it.Kind != "uninspected_egress" {
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

// firstEvidence is the first evidence line, rendered for text display.
func firstEvidence(ev []model.EvidenceItem) string {
	if len(ev) == 0 {
		return ""
	}
	return ev[0].String()
}

// criticalSummary picks the highest-severity item as the one-line headline.
func criticalSummary(items []PostureItem) string {
	for _, it := range items {
		if it.Severity >= 3 {
			return it.Title + " — act now."
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
// excluded: an idle-but-working agent legitimately opens no sockets for long
// stretches, so its silence is ambiguous. File and transcript telemetry are
// not ambiguous — an active harness touches files constantly.
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
		if c.Name == "eslogger" && c.Running && !c.Abandoned && st.ESService != nil {
			svcItems := esServiceItems(now, *st.ESService)
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
					Kind: "collector_silent", ID: c.Name,
					Title:    humanCollectorSilentTitle(c.Name) + " is producing nothing",
					Severity: 2,
					Detail:   "collector is running but has published no events since daemon start — telemetry source may be dead",
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
				Kind: "collector_silent", ID: c.Name,
				Title:    humanCollectorSilentTitle(c.Name) + " went quiet",
				Severity: 2,
				Detail:   "no events for more than " + window.String() + " while agents are active — check the telemetry source",
			})
		}
	}
	return items
}

// esServiceItems turns one root-service probe into posture items. The probe
// is best-effort: launchctl errors are already folded into the state string.
// A flooding writer supersedes every other eslogger item: the tailer and the
// root service can both read healthy while the writer drowns them in
// garbage, and that is the failure the operator needs to see first. Events
// arriving long after they happened (esServiceLagging) come next: the spool
// is written and the tailer keeps up, yet every file flag and resource
// episode sees the activity that late. A sustained burst of otherwise-valid
// lines the tailer cannot keep up with (esServiceBehind) is a lesser item:
// the writer is fine, the reader is behind.
func esServiceItems(now time.Time, s collect.ESServiceSnapshot) []PostureItem {
	if s.Losing {
		return []PostureItem{{Kind: "collector_silent", ID: "eslogger", Title: "File monitoring evidence was lost", Severity: 2, Detail: esLossDetail(s)}}
	}
	if esServiceFlooding(now, s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring writer is flooding",
			Severity: 2,
			Detail:   esFloodingDetail(s),
		}}
	}
	if esServiceLagging(now, s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is running late",
			Severity: 2,
			Detail:   esLaggingDetail(s),
		}}
	}
	if esServiceBehind(now, s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is falling behind",
			Severity: 1,
			Detail:   esBehindDetail(s),
		}}
	}
	// A spool exists, so file telemetry was on; the service is gone.
	if s.State == "not-loaded" && !s.SpoolMtime.IsZero() {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is off",
			Severity: 2,
			Detail: "the file telemetry helper is not loaded — enable it in Setup & Permissions → File Telemetry, " +
				"then approve Secure Agent in Login Items and Full Disk Access",
		}}
	}
	var items []PostureItem
	if esServiceFailing(s.State) {
		next := "check /var/log/secure-agent-esd.log"
		if esServiceRefused(s.State) {
			next = esReregisterHint + ", then " + next
		}
		items = append(items, PostureItem{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring service is failing",
			Severity: 2,
			Detail:   "root ES collector service state: " + s.State + " — spool " + s.SpoolStateAt(now) + " — " + next,
		})
	} else if now.Sub(s.SpoolMtime) > 30*time.Minute {
		detail := "root ES collector reports " + s.State + " but the spool " + s.SpoolStateAt(now) + " — file telemetry may be blind"
		// An ad-hoc signed build's privacy grant is bound to that build: a
		// collector binary installed after the last spool write lost it.
		if esServiceRunning(s.State) && !s.SpoolMtime.IsZero() && s.HelperMtime.After(s.SpoolMtime) {
			detail = "root ES collector reports running but the spool " + s.SpoolStateAt(now) +
				" — the helper binary was replaced after the last write; grant Full Disk Access again for Secure Agent"
		}
		items = append(items, PostureItem{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring service is not writing",
			Severity: 2,
			Detail:   detail,
		})
	}
	return items
}

func esLossDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("at least %d unread spool bytes were skipped or overwritten during this daemon run; later healthy delivery cannot recover that evidence", s.BytesLost)
}

// esFloodFreshWindow: a flood verdict needs a spool written this recently.
const esFloodFreshWindow = 2 * time.Minute

// esServiceFailing reports a root ES service state that means the writer is
// crash-looping (spawn scheduled) or has exited. A running service whose
// state carries an earlier non-zero exit ("running (last exit 1)") was
// restarted and is up; the spool's age judges whether it writes.
func esServiceFailing(state string) bool {
	if esServiceRunning(state) {
		return false
	}
	return strings.Contains(state, "spawn") || strings.Contains(state, "exit")
}

// esServiceRefused reports a root ES service launchd will not bring up: last
// exit 78 (EX_CONFIG, launchd refusing the spawn; the helper never exits 78)
// while not running, or spawn scheduled after a nonzero exit. The menu bar
// Doctor's Re-register binds the job to the installed build again.
func esServiceRefused(state string) bool {
	if esServiceRunning(state) {
		return false
	}
	// parseLaunchctlState notes only nonzero exits: " (last exit 78: EX_CONFIG)".
	_, note, ok := strings.Cut(state, " (last exit ")
	if !ok {
		return false
	}
	head, _, _ := strings.Cut(strings.TrimSuffix(note, ")"), ":")
	code, err := strconv.Atoi(head)
	if err != nil || code == 0 {
		return false
	}
	return code == esExConfig || strings.HasPrefix(state, "spawn scheduled")
}

// esExConfig is sysexits' EX_CONFIG, launchd's code for a job it could not spawn.
const esExConfig = 78

// esReregisterHint is the action both the posture and doctor details name
// for a refused service.
const esReregisterHint = "Re-register it from Run Doctor… in the menu bar"

// esServiceRunning reports a running root ES service, with or without an
// earlier exit noted after the state.
func esServiceRunning(state string) bool {
	return state == "running" || strings.HasPrefix(state, "running (")
}

// esServiceFlooding reports a writer producing mostly-unparseable lines —
// garbage, not a burst the tailer merely fell behind on. Skipping alone
// (s.Flooding) no longer counts: SpoolStats.Lines counts only lines the
// scanner read, so UnparsedShare over half means those READ lines were
// mostly garbage, whatever the tailer skipped in bulk notwithstanding.
func esServiceFlooding(now time.Time, s collect.ESServiceSnapshot) bool {
	// Garbage in a spool nobody writes any more is leftover, not a flood:
	// the last drain's verdict counts only while the writer is still active.
	if s.SpoolMtime.IsZero() || now.Sub(s.SpoolMtime) > esFloodFreshWindow {
		return false
	}
	return s.UnparsedShare > 0.5
}

// esFloodingDetail is the shared wording for the flooding (garbage) failure:
// posture and doctor report the same facts.
func esFloodingDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("%.0f%% of lines in the last drain did not parse — the writer is producing garbage",
		s.UnparsedShare*100)
}

// esLagWindow: file events delivered later than this after they happened
// are too late for a flag or a resource episode to use. The root collector
// restarts eslogger after 30 s past 60 s, so a lag this long means it has not.
const esLagWindow = 2 * time.Minute

// esServiceLagging reports file events reaching the daemon esLagWindow or
// more after they happened, while the writer is still writing.
func esServiceLagging(now time.Time, s collect.ESServiceSnapshot) bool {
	if s.SpoolMtime.IsZero() || now.Sub(s.SpoolMtime) > esFloodFreshWindow || s.NewestEventAt == nil {
		return false
	}
	return time.Duration(s.LagSeconds)*time.Second >= esLagWindow
}

// esLaggingDetail is the shared wording for the late-delivery failure:
// posture and doctor report the same facts.
func esLaggingDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("file monitoring delivery is %s behind; the newest accepted event happened at %s — file flags and resource episodes see delayed activity",
		time.Duration(s.LagSeconds)*time.Second, s.NewestEventAt.Local().Format("15:04:05"))
}

// esBehindWindow: a skip shorter than this is normal load on a healthy
// writer, not a reader that is stuck falling behind.
const esBehindWindow = 60 * time.Second

// esServiceBehind reports a healthy writer (not garbage) whose valid-line
// bursts have made the tailer skip past its per-tick budget for longer than
// esBehindWindow — the reader is behind, not broken. Garbage supersedes this:
// esServiceFlooding is checked first by callers and takes priority.
func esServiceBehind(now time.Time, s collect.ESServiceSnapshot) bool {
	if s.SpoolMtime.IsZero() || now.Sub(s.SpoolMtime) > esFloodFreshWindow {
		return false
	}
	if esServiceFlooding(now, s) {
		return false
	}
	return s.Flooding && s.FloodingSince != nil && now.Sub(*s.FloodingSince) > esBehindWindow
}

// esBehindDetail is the shared wording for the falling-behind failure:
// posture and doctor report the same facts. spoolDrainBudget (4 MiB per
// 200ms tick, in collect/spool.go) is a fixed 20 MB/s reader limit.
func esBehindDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("skipping since %s, last drain skipped %.1f MB — the reader's limit is 20 MB/s",
		s.FloodingSince.Local().Format("15:04"), float64(s.BytesSkipped)/(1<<20))
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
