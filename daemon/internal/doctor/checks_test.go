package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func timeAt(t time.Time) *time.Time { return &t }

// The checks are pure functions of the gathered facts.
func TestDoctorChecksFromFacts(t *testing.T) {
	now := time.Now().UTC()
	steady := Facts{Now: now, Status: posture.Status{ActiveAgents: 2}}
	cases := []struct {
		name  string
		check func(Facts) (string, string)
		f     Facts
		state string
		has   string
	}{
		{"collector down", checkCollectors, func() Facts {
			f := steady
			f.Status.Collectors = []supervise.Health{{Name: "eslogger", Running: true, Abandoned: true}, {Name: "netsampler"}}
			return f
		}(), Fail, "down: eslogger (abandoned), netsampler (stopped)"},
		{"collectors up", checkCollectors, func() Facts {
			f := steady
			f.Status.Collectors = []supervise.Health{{Name: "netsampler", Running: true}}
			return f
		}(), Pass, "1 collectors running"},
		{"disabled file collector", checkCollectors, func() Facts {
			f := steady
			disabled := false
			f.Status.FileTelemetryEnabled = &disabled
			f.Status.Collectors = []supervise.Health{{Name: "eslogger"}, {Name: "netsampler", Running: true}}
			return f
		}(), Pass, "1 collectors running"},
		{"harness without trace", checkTraceCoverage, func() Facts {
			f := steady
			f.SeenByHarness = map[string]int{"claude": 2, "codex": 1}
			f.traceByHarness = map[string]int{"claude": 9}
			return f
		}(), Fail, "no trace rows: codex"},
		{"all harnesses traced", checkTraceCoverage, func() Facts {
			f := steady
			f.SeenByHarness = map[string]int{"claude": 2}
			f.traceByHarness = map[string]int{"claude": 9}
			return f
		}(), Pass, "1 harnesses traced"},
		{"traced harnesses named", checkTraceCoverage, func() Facts {
			f := steady
			f.SeenByHarness = map[string]int{"openclaw": 3, "claude": 2}
			f.traceByHarness = map[string]int{"openclaw": 12, "claude": 9}
			return f
		}(), Pass, "2 harnesses traced: claude (2 sessions), openclaw (3 sessions)"},
		{"sessions seen since boot count, not only started", checkTraceCoverage, func() Facts {
			f := steady
			f.sessionsByHarness = map[string]int{"codex": 1}
			f.SeenByHarness = map[string]int{"codex": 5, "openclaw": 3}
			f.traceByHarness = map[string]int{"codex": 40, "openclaw": 12}
			return f
		}(), Pass, "2 harnesses traced: codex (5 sessions), openclaw (3 sessions)"},
		{"collector source, watermark and last poll", checkCollectors, func() Facts {
			f := steady
			f.Status.Collectors = []supervise.Health{{Name: "openclaw", Running: true, Source: "/x/lcm.db", Watermark: 42, LastPoll: "2026-09-23T04:00:00Z"}}
			return f
		}(), Pass, "openclaw /x/lcm.db @ 42 polled 2026-09-23T04:00:00Z"},
		{"collector source printed on a failing check", checkCollectors, func() Facts {
			f := steady
			f.Status.Collectors = []supervise.Health{{Name: "eslogger"}, {Name: "opencode", Running: true, Source: "/y/opencode.db", Watermark: 7, LastPoll: "2026-09-23T04:00:00Z"}}
			return f
		}(), Fail, "down: eslogger (stopped) · opencode /y/opencode.db @ 7 polled 2026-09-23T04:00:00Z"},
		{"spool loss is file telemetry's, not a silent collector", checkCollectors, func() Facts {
			f := steady
			f.Status.Collectors = []supervise.Health{{Name: "eslogger", Running: true, LastProduced: now.Format(time.RFC3339)}}
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: now, Losing: true, BytesLost: 9}
			return f
		}(), Pass, "1 collectors running"},
		{"still failing writes", CheckStorage, func() Facts {
			f := steady
			at := now.Add(-time.Hour)
			f.Status.StorageHealth = &store.WriteHealth{Failures: 2, LastFailureAt: &at, Active: []string{"events"}}
			return f
		}(), Fail, "still failing: events"},
		{"recent recovered write failure", CheckStorage, func() Facts {
			f := steady
			at := now.Add(-time.Minute)
			f.Status.StorageHealth = &store.WriteHealth{Failures: 2, LastFailureAt: &at, Active: []string{}}
			return f
		}(), Pass, "new writes recovered; 2 earlier failures"},
		{"old recovered write failure", CheckStorage, func() Facts {
			f := steady
			at := now.Add(-collect.LossWindow - time.Minute)
			f.Status.StorageHealth = &store.WriteHealth{Failures: 2, LastFailureAt: &at, Active: []string{}}
			return f
		}(), Pass, "2 earlier failures may have left evidence gaps"},
		{"recovered write failure marked seen", CheckStorage, func() Facts {
			f := steady
			at := now.Add(-time.Minute)
			f.Status.StorageHealth = &store.WriteHealth{Failures: 2, LastFailureAt: &at, Active: []string{}}
			f.LossSeen = new(collect.LossSeen)
			f.LossSeen.Mark(now)
			return f
		}(), Pass, "new writes recovered"},
		{"unnamed sessions", checkSessionIdentity, func() Facts {
			f := steady
			f.sessionsTotal, f.sessionsNamed = 10, 7
			return f
		}(), Fail, "7 of 10 sessions since boot"},
		{"session identity waits out the boot window", checkSessionIdentity, func() Facts {
			f := steady
			f.Grace = true
			f.sessionsTotal, f.sessionsNamed = 10, 7
			return f
		}(), Skip, GraceDetail},
		{"no sessions since boot", checkSessionIdentity, steady, Skip, "no sessions since boot"},
		{"attribution drop", checkSessionRepo, func() Facts {
			f := steady
			f.sessionsByHarness = map[string]int{"claude": 3}
			return f
		}(), Fail, "0 of 3 named sessions since boot carry a workspace"},
		{"repo coverage", checkSessionRepo, func() Facts {
			f := steady
			f.sessionsWithWorkspace, f.sessionsWithGitWorkspace, f.sessionsGitWRepo = 4, 4, 1
			return f
		}(), Fail, "1 of 4"},
		{"non-git workspaces do not count against repo coverage", checkSessionRepo, func() Facts {
			f := steady
			f.sessionsWithWorkspace, f.sessionsWithGitWorkspace, f.sessionsGitWRepo = 10, 2, 2
			return f
		}(), Pass, "2 of 2"},
		{"session flood", checkSessionRate, func() Facts {
			f := steady
			f.sessionsLastHour = 15
			return f
		}(), Fail, "budget 14"},
		{"claude unpriced", checkPricing, func() Facts {
			f := steady
			f.claudePriced, f.claudeUnpriced, f.allUnpriced, f.allCalls = 8, 2, 5, 20
			return f
		}(), Fail, "8 of 10 Claude calls priced (80%) · all models: 5 of 20 calls unpriced"},
		{"evicting inside a day", checkRetention, func() Facts {
			f := steady
			f.retention = []store.KindRetention{
				{Kind: 12, Name: "tool-call", Rows: 50000, Budget: 50000, HorizonTS: now.Add(-3 * time.Hour).Format(time.RFC3339)},
				{Kind: 1, Name: "file-write", Rows: 150000, Budget: 150000, HorizonTS: now.Add(-72 * time.Hour).Format(time.RFC3339)},
			}
			return f
		}(), Fail, "tool-call 50000/50000 rows, oldest 3h0m0s"},
		{"at budget but keeps a day", checkRetention, func() Facts {
			f := steady
			f.retention = []store.KindRetention{{Kind: 1, Name: "file-write", Rows: 150000, Budget: 150000, HorizonTS: now.Add(-72 * time.Hour).Format(time.RFC3339)}}
			return f
		}(), Pass, "1 kinds within budget"},
		{"ring kind keeps minutes, its record keeps days", checkRetention, func() Facts {
			f := steady
			f.retention = []store.KindRetention{
				{Kind: 0, Name: "file-open", Rows: 40300, Budget: 40000, HorizonTS: now.Add(-2 * time.Minute).Format(time.RFC3339), Ring: true,
					RecordRows: 300, RecordBudget: 20000},
				{Kind: 3, Name: "exec", Rows: 10000, Budget: 10000, HorizonTS: now.Add(-5 * time.Minute).Format(time.RFC3339), Ring: true,
					RecordRows: 20000, RecordBudget: 20000, RecordHorizonTS: now.Add(-50 * time.Hour).Format(time.RFC3339)},
			}
			return f
		}(), Pass, "2 kinds within budget; newest rows only (record rows keep days): file-open 2m0s, exec 5m0s"},
		{"record rows evicted inside a day", checkRetention, func() Facts {
			f := steady
			f.retention = []store.KindRetention{{Kind: 0, Name: "file-open", Rows: 60000, Budget: 40000, HorizonTS: now.Add(-2 * time.Minute).Format(time.RFC3339), Ring: true,
				RecordRows: 20000, RecordBudget: 20000, RecordHorizonTS: now.Add(-3 * time.Hour).Format(time.RFC3339)}}
			return f
		}(), Fail, "at budget with under 24h kept: file-open record 20000/20000 rows, oldest 3h0m0s"},
		{"spool stale", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: now.Add(-25 * time.Minute)}
			return f
		}(), Fail, "spool not written for 25 min"},
		{"service not loaded", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "not-loaded"}
			return f
		}(), Fail, "not loaded"},
		{"short flood burst is not yet behind", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), Flooding: true, FloodingSince: timeAt(now.Add(-5 * time.Second))}
			return f
		}(), Pass, "running"},
		{"sustained flood burst reads as falling behind", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), Flooding: true, FloodingSince: timeAt(now.Add(-2 * time.Minute))}
			return f
		}(), Fail, "skipping since"},
		{"unparsed share alone", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), UnparsedShare: 0.9}
			return f
		}(), Fail, "did not parse"},
		{"file events delivered two hours late", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: now, NewestEventAt: timeAt(now.Add(-2 * time.Hour)), LagSeconds: 7200}
			return f
		}(), Fail, "delivery is 2h0m0s behind"},
		{"file events delivered on time", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: now, NewestEventAt: timeAt(now), LagSeconds: 1}
			return f
		}(), Pass, "running"},
		{"low unparsed share is not flooding", CheckFileTelemetry, func() Facts {
			f := steady
			f.Status.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: now, UnparsedShare: 0.1}
			return f
		}(), Pass, "running"},
	}
	for _, tc := range cases {
		state, detail := tc.check(tc.f)
		if state != tc.state || !strings.Contains(detail, tc.has) {
			t.Errorf("%s: %s %q, want %s containing %q", tc.name, state, detail, tc.state, tc.has)
		}
	}
}
