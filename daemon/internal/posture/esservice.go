package posture

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
)

// ESServiceItems turns one root-service probe into posture items. The probe
// is best-effort: launchctl errors are already folded into the state string.
// A flooding writer supersedes every other eslogger item: the tailer and the
// root service can both read healthy while the writer drowns them in
// garbage, and that is the failure the operator needs to see first. Events
// arriving long after they happened (ESServiceLagging) come next: the spool
// is written and the tailer keeps up, yet every file flag and resource
// episode sees the activity that late. A sustained burst of otherwise-valid
// lines the tailer cannot keep up with (ESServiceBehind) is a lesser item:
// the writer is fine, the reader is behind.
func ESServiceItems(now time.Time, s collect.ESServiceSnapshot) []PostureItem {
	if s.Losing {
		return []PostureItem{{Kind: "collector_silent", ID: "eslogger", Title: "File monitoring evidence was lost", Severity: 2, Detail: ESLossDetail(s)}}
	}
	if title, detail := CollectorFailure(now, s); title != "" {
		return []PostureItem{{Kind: "collector_silent", ID: "eslogger", Title: title, Severity: 2, Detail: detail}}
	}
	if ESServiceFlooding(now, s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring writer is flooding",
			Severity: 2,
			Detail:   ESFloodingDetail(s),
		}}
	}
	if ESServiceLagging(now, s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is running late",
			Severity: 2,
			Detail:   ESLaggingDetail(s),
		}}
	}
	if ESServiceBehind(now, s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is falling behind",
			Severity: 1,
			Detail:   ESBehindDetail(s),
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
	if ESServiceFailing(s.State) {
		next := "check /var/log/secure-agent-esd.log"
		if ESServiceRefused(s.State) {
			next = ESReregisterHint + ", then " + next
		}
		items = append(items, PostureItem{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring service is failing",
			Severity: 2,
			Detail:   "root ES collector service state: " + s.State + " — spool " + s.SpoolStateAt(now) + " — " + next,
		})
	} else if now.Sub(s.SpoolMtime) > 30*time.Minute {
		if ESServiceRunning(s.State) && s.Collector != nil && s.Collector.Fresh(now) && s.Collector.State == "collecting" {
			return []PostureItem{{Kind: "collector_idle", ID: "eslogger", Title: "No recent file activity", Detail: "The file collector reports that it is ready. No recent file events were observed."}}
		}
		detail := "root ES collector reports " + s.State + " but the spool " + s.SpoolStateAt(now) + " — file telemetry may be blind"
		// An ad-hoc signed build's privacy grant is bound to that build: a
		// collector binary installed after the last spool write lost it.
		if ESServiceRunning(s.State) && !s.SpoolMtime.IsZero() && s.HelperMtime.After(s.SpoolMtime) {
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

func CollectorFailure(now time.Time, s collect.ESServiceSnapshot) (string, string) {
	if s.Collector == nil || !s.Collector.Fresh(now) || !ESServiceRunning(s.State) {
		return "", ""
	}
	switch s.Collector.State {
	case "permission_denied":
		return "File monitoring needs Full Disk Access", "macOS denied the file collector authorization. Grant Full Disk Access to Secure Agent in System Settings → Privacy & Security → Full Disk Access. The collector will retry automatically."
	case "failed", "stopped":
		return "File monitoring collector is unavailable", "The file collector reported " + s.Collector.State + ". Check the file telemetry helper in Setup & Permissions."
	}
	return "", ""
}

func ESLossDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("at least %d unread spool bytes were skipped or overwritten during this daemon run; later healthy delivery cannot recover that evidence", s.BytesLost)
}

// esFloodFreshWindow: a flood verdict needs a spool written this recently.
const esFloodFreshWindow = 2 * time.Minute

// ESServiceFailing reports a root ES service state that means the writer is
// crash-looping (spawn scheduled) or has exited. A running service whose
// state carries an earlier non-zero exit ("running (last exit 1)") was
// restarted and is up; the spool's age judges whether it writes.
func ESServiceFailing(state string) bool {
	if ESServiceRunning(state) {
		return false
	}
	return strings.Contains(state, "spawn") || strings.Contains(state, "exit")
}

// ESServiceRefused reports a root ES service launchd will not bring up: last
// exit 78 (EX_CONFIG, launchd refusing the spawn; the helper never exits 78)
// while not running, or spawn scheduled after a nonzero exit. The menu bar
// Doctor's Re-register binds the job to the installed build again.
func ESServiceRefused(state string) bool {
	if ESServiceRunning(state) {
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

// ESReregisterHint is the action both the posture and doctor details name
// for a refused service.
const ESReregisterHint = "Re-register it from Run Doctor… in the menu bar"

// ESServiceRunning reports a running root ES service, with or without an
// earlier exit noted after the state.
func ESServiceRunning(state string) bool {
	return state == "running" || strings.HasPrefix(state, "running (")
}

// ESServiceFlooding reports a writer producing mostly-unparseable lines —
// garbage, not a burst the tailer merely fell behind on. Skipping alone
// (s.Flooding) no longer counts: SpoolStats.Lines counts only lines the
// scanner read, so UnparsedShare over half means those READ lines were
// mostly garbage, whatever the tailer skipped in bulk notwithstanding.
func ESServiceFlooding(now time.Time, s collect.ESServiceSnapshot) bool {
	// Garbage in a spool nobody writes any more is leftover, not a flood:
	// the last drain's verdict counts only while the writer is still active.
	if s.SpoolMtime.IsZero() || now.Sub(s.SpoolMtime) > esFloodFreshWindow {
		return false
	}
	return s.UnparsedShare > 0.5
}

// ESFloodingDetail is the shared wording for the flooding (garbage) failure:
// posture and doctor report the same facts.
func ESFloodingDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("%.0f%% of lines in the last drain did not parse — the writer is producing garbage",
		s.UnparsedShare*100)
}

// esLagWindow: file events delivered later than this after they happened
// are too late for a flag or a resource episode to use. The root collector
// restarts eslogger after 30 s past 60 s, so a lag this long means it has not.
const esLagWindow = 2 * time.Minute

// ESServiceLagging reports file events reaching the daemon esLagWindow or
// more after they happened, while the writer is still writing.
func ESServiceLagging(now time.Time, s collect.ESServiceSnapshot) bool {
	if s.SpoolMtime.IsZero() || now.Sub(s.SpoolMtime) > esFloodFreshWindow || s.NewestEventAt == nil {
		return false
	}
	return time.Duration(s.LagSeconds)*time.Second >= esLagWindow
}

// ESLaggingDetail is the shared wording for the late-delivery failure:
// posture and doctor report the same facts.
func ESLaggingDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("file monitoring delivery is %s behind; the newest accepted event happened at %s — file flags and resource episodes see delayed activity",
		time.Duration(s.LagSeconds)*time.Second, s.NewestEventAt.Local().Format("15:04:05"))
}

// esBehindWindow: a skip shorter than this is normal load on a healthy
// writer, not a reader that is stuck falling behind.
const esBehindWindow = 60 * time.Second

// ESServiceBehind reports a healthy writer (not garbage) whose valid-line
// bursts have made the tailer skip past its per-tick budget for longer than
// esBehindWindow — the reader is behind, not broken. Garbage supersedes this:
// ESServiceFlooding is checked first by callers and takes priority.
func ESServiceBehind(now time.Time, s collect.ESServiceSnapshot) bool {
	if s.SpoolMtime.IsZero() || now.Sub(s.SpoolMtime) > esFloodFreshWindow {
		return false
	}
	if ESServiceFlooding(now, s) {
		return false
	}
	return s.Flooding && s.FloodingSince != nil && now.Sub(*s.FloodingSince) > esBehindWindow
}

// ESBehindDetail is the shared wording for the falling-behind failure:
// posture and doctor report the same facts. spoolDrainBudget (4 MiB per
// 200ms tick, in collect/spool.go) is a fixed 20 MB/s reader limit.
func ESBehindDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("skipping since %s, last drain skipped %.1f MB — the reader's limit is 20 MB/s",
		s.FloodingSince.Local().Format("15:04"), float64(s.BytesSkipped)/(1<<20))
}
