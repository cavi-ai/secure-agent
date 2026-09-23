package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// getDoctor serves GET /doctor against st with a fixed status. HOME is
// hermetic so the hook-registration check never reads a real settings file.
func getDoctor(t *testing.T, st *store.Store, status Status) (DoctorReport, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	a := newTestAPI("", st, nil, func() Status { return status })
	rec := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/doctor", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /doctor: status %d body %q", rec.Code, rec.Body.String())
	}
	var rep DoctorReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	return rep, rec.Body.String()
}

func doctorCheckByID(t *testing.T, rep DoctorReport, id string) DoctorCheck {
	t.Helper()
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q missing from %+v", id, rep.Checks)
	return DoctorCheck{}
}

func TestDoctorEmptyStore(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, body := getDoctor(t, st, Status{Running: true, Version: "1.2.3", Uptime: "1h0m0s"})

	if !strings.Contains(body, `"checks":[{`) {
		t.Fatalf("checks must be a non-null array: %s", body)
	}
	if rep.Grace || rep.Version != "1.2.3" || rep.Uptime != "1h0m0s" || rep.GeneratedAt == "" {
		t.Fatalf("header = %+v", rep)
	}
	if len(rep.Checks) != len(doctorProbes) {
		t.Fatalf("got %d checks, want %d", len(rep.Checks), len(doctorProbes))
	}
	var sum DoctorSummary
	for i, c := range rep.Checks {
		if c.ID != doctorProbes[i].id {
			t.Fatalf("check %d = %q, want %q (fixed order)", i, c.ID, doctorProbes[i].id)
		}
		switch c.State {
		case doctorPass:
			sum.Pass++
		case doctorFail:
			sum.Fail++
		case doctorSkip:
			sum.Skip++
		default:
			t.Fatalf("check %s state %q", c.ID, c.State)
		}
		if (c.State == doctorFail) != (c.Fix != "") && c.ID != "bus" {
			t.Fatalf("check %s: fix %q must be set exactly on fail", c.ID, c.Fix)
		}
	}
	if rep.Summary != sum {
		t.Fatalf("summary %+v, counted %+v", rep.Summary, sum)
	}
	for id, want := range map[string]string{
		"hook-active":      doctorSkip,
		"tool-pairing":     doctorPass,
		"session-identity": doctorSkip,
		"hook-registered":  doctorFail, // hermetic HOME has no settings.json
		"file-telemetry":   doctorSkip,
		"egress-routing":   doctorPass,
		"bus":              doctorPass,
	} {
		if c := doctorCheckByID(t, rep, id); c.State != want {
			t.Errorf("%s = %s (%s), want %s", id, c.State, c.Detail, want)
		}
	}
	if c := doctorCheckByID(t, rep, "hook-registered"); c.Fix != "Run Setup → Harness hooks" {
		t.Errorf("hook-registered fix = %q", c.Fix)
	}

	rec := httptest.NewRecorder()
	newTestAPI("", st, nil, func() Status { return Status{} }).buildMux().
		ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/doctor", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /doctor: status %d, want 405", rec.Code)
	}
}

func TestDoctorBootGraceSkipsSteadyStateChecks(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{
		Running: true, Uptime: "2m0s", ActiveAgents: 3,
		Collectors: []supervise.Health{{Name: "netsampler", Running: false}},
		// A stale spool is not a failure inside the boot window.
		ESService: &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now().Add(-time.Hour)},
	})
	if !rep.Grace {
		t.Fatal("uptime 2m must report grace")
	}
	for _, id := range []string{"collectors", "trace-coverage", "session-repo", "session-rate"} {
		if c := doctorCheckByID(t, rep, id); c.State != doctorSkip || c.Detail != doctorGraceDetail {
			t.Errorf("%s = %s (%q), want skip inside the boot window", id, c.State, c.Detail)
		}
	}
	if c := doctorCheckByID(t, rep, "file-telemetry"); c.State != doctorPass {
		t.Errorf("file-telemetry in grace = %s (%s), want pass", c.State, c.Detail)
	}
}

func TestDoctorToolPairingFailsOnDuplicatePair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// Rows with a NULL session id are distinct under the unique call index,
	// so a legacy writer could store the same call twice.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(`INSERT INTO events (kind, ts, session_id, call_id) VALUES (?, ?, NULL, 'dup')`,
			int(event.KindToolCall), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s"})
	c := doctorCheckByID(t, rep, "tool-pairing")
	if c.State != doctorFail || !strings.Contains(c.Detail, "1 duplicate") || c.Fix == "" {
		t.Fatalf("tool-pairing = %+v, want fail naming 1 duplicate pair with a fix", c)
	}
	if rep.Summary.Fail < 1 {
		t.Fatalf("summary %+v must count the failure", rep.Summary)
	}
}

func TestDoctorFileTelemetryFailsOnCrashLoop(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s",
		ESService: &collect.ESServiceSnapshot{State: "spawn scheduled"}})
	c := doctorCheckByID(t, rep, "file-telemetry")
	if c.State != doctorFail || !strings.Contains(c.Detail, "spawn scheduled") || !strings.Contains(c.Fix, "Full Disk Access") {
		t.Fatalf("file-telemetry = %+v, want fail with the service state and the FDA fix", c)
	}
}

func TestDoctorFileTelemetryFailsOnFlood(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s",
		ESService: &collect.ESServiceSnapshot{State: "running", Flooding: true, UnparsedShare: 0.97, BytesSkipped: 6 << 20}})
	c := doctorCheckByID(t, rep, "file-telemetry")
	if c.State != doctorFail || !strings.Contains(c.Detail, "did not parse") ||
		!strings.Contains(c.Fix, "Reinstall the file telemetry helper from the Setup card") {
		t.Fatalf("file-telemetry = %+v, want fail naming the unparsed share with the reinstall fix", c)
	}
}

func TestDoctorHookActiveFailsWithAgentsAndNoHookEvents(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", ActiveAgents: 3})
	c := doctorCheckByID(t, rep, "hook-active")
	if c.State != doctorFail || !strings.Contains(c.Fix, "Setup") || !strings.Contains(c.Fix, "Bash") {
		t.Fatalf("hook-active = %+v, want fail naming the Setup step and Bash tool calls", c)
	}

	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: time.Now(), Detail: "Bash"})
	rep, _ = getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", ActiveAgents: 3})
	if c := doctorCheckByID(t, rep, "hook-active"); c.State != doctorPass || c.Detail != "1 hook events in 24h" {
		t.Fatalf("hook-active after a hook event = %+v, want pass", c)
	}
}

func TestDoctorEgressAndBusFail(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", ProxyEnabled: true, UninspectedEgress: 5, BusDrops: 7})
	if c := doctorCheckByID(t, rep, "egress-routing"); c.State != doctorFail || !strings.Contains(c.Detail, "5") || !strings.Contains(c.Fix, "agent-env.sh") {
		t.Fatalf("egress-routing = %+v, want fail with the count and the routing fix", c)
	}
	if c := doctorCheckByID(t, rep, "bus"); c.State != doctorFail || !strings.Contains(c.Detail, "7") || c.Fix != "" {
		t.Fatalf("bus = %+v, want fail with the count and no fix", c)
	}
}

// The checks are pure functions of the gathered facts.
func TestDoctorChecksFromFacts(t *testing.T) {
	now := time.Now().UTC()
	steady := doctorFacts{now: now, st: Status{ActiveAgents: 2}}
	cases := []struct {
		name  string
		check func(doctorFacts) (string, string)
		f     doctorFacts
		state string
		has   string
	}{
		{"collector down", checkCollectors, func() doctorFacts {
			f := steady
			f.st.Collectors = []supervise.Health{{Name: "eslogger", Running: true, Abandoned: true}, {Name: "netsampler"}}
			return f
		}(), doctorFail, "down: eslogger (abandoned), netsampler (stopped)"},
		{"collectors up", checkCollectors, func() doctorFacts {
			f := steady
			f.st.Collectors = []supervise.Health{{Name: "netsampler", Running: true}}
			return f
		}(), doctorPass, "1 collectors running"},
		{"harness without trace", checkTraceCoverage, func() doctorFacts {
			f := steady
			f.seenByHarness = map[string]int{"claude": 2, "codex": 1}
			f.traceByHarness = map[string]int{"claude": 9}
			return f
		}(), doctorFail, "no trace rows: codex"},
		{"all harnesses traced", checkTraceCoverage, func() doctorFacts {
			f := steady
			f.seenByHarness = map[string]int{"claude": 2}
			f.traceByHarness = map[string]int{"claude": 9}
			return f
		}(), doctorPass, "1 harnesses traced"},
		{"traced harnesses named", checkTraceCoverage, func() doctorFacts {
			f := steady
			f.seenByHarness = map[string]int{"openclaw": 3, "claude": 2}
			f.traceByHarness = map[string]int{"openclaw": 12, "claude": 9}
			return f
		}(), doctorPass, "2 harnesses traced: claude (2 sessions), openclaw (3 sessions)"},
		{"sessions seen since boot count, not only started", checkTraceCoverage, func() doctorFacts {
			f := steady
			f.sessionsByHarness = map[string]int{"codex": 1}
			f.seenByHarness = map[string]int{"codex": 5, "openclaw": 3}
			f.traceByHarness = map[string]int{"codex": 40, "openclaw": 12}
			return f
		}(), doctorPass, "2 harnesses traced: codex (5 sessions), openclaw (3 sessions)"},
		{"collector source, watermark and last poll", checkCollectors, func() doctorFacts {
			f := steady
			f.st.Collectors = []supervise.Health{{Name: "openclaw", Running: true, Source: "/x/lcm.db", Watermark: 42, LastPoll: "2026-09-23T04:00:00Z"}}
			return f
		}(), doctorPass, "openclaw /x/lcm.db @ 42 polled 2026-09-23T04:00:00Z"},
		{"collector source printed on a failing check", checkCollectors, func() doctorFacts {
			f := steady
			f.st.Collectors = []supervise.Health{{Name: "eslogger"}, {Name: "opencode", Running: true, Source: "/y/opencode.db", Watermark: 7, LastPoll: "2026-09-23T04:00:00Z"}}
			return f
		}(), doctorFail, "down: eslogger (stopped) · opencode /y/opencode.db @ 7 polled 2026-09-23T04:00:00Z"},
		{"unnamed sessions", checkSessionIdentity, func() doctorFacts {
			f := steady
			f.sessionsTotal, f.sessionsNamed = 10, 7
			return f
		}(), doctorFail, "7 of 10"},
		{"attribution drop", checkSessionRepo, func() doctorFacts {
			f := steady
			f.sessionsByHarness = map[string]int{"claude": 3}
			return f
		}(), doctorFail, "0 of 3 named sessions since boot carry a workspace"},
		{"repo coverage", checkSessionRepo, func() doctorFacts {
			f := steady
			f.sessionsWithWorkspace, f.sessionsWRepo = 4, 1
			return f
		}(), doctorFail, "1 of 4"},
		{"session flood", checkSessionRate, func() doctorFacts {
			f := steady
			f.sessionsLastHour = 15
			return f
		}(), doctorFail, "budget 14"},
		{"claude unpriced", checkPricing, func() doctorFacts {
			f := steady
			f.claudePriced, f.claudeUnpriced, f.allUnpriced, f.allCalls = 8, 2, 5, 20
			return f
		}(), doctorFail, "8 of 10 Claude calls priced (80%) · all models: 5 of 20 calls unpriced"},
		{"evicting inside a day", checkRetention, func() doctorFacts {
			f := steady
			f.retention = []store.KindRetention{
				{Kind: 12, Name: "tool-call", Rows: 50000, Budget: 50000, OldestTS: now.Add(-3 * time.Hour).Format(time.RFC3339)},
				{Kind: 0, Name: "file-open", Rows: 40000, Budget: 40000, OldestTS: now.Add(-72 * time.Hour).Format(time.RFC3339)},
			}
			return f
		}(), doctorFail, "tool-call 50000/50000 rows, oldest 3h0m0s"},
		{"at budget but keeps a day", checkRetention, func() doctorFacts {
			f := steady
			f.retention = []store.KindRetention{{Kind: 0, Name: "file-open", Rows: 40000, Budget: 40000, OldestTS: now.Add(-72 * time.Hour).Format(time.RFC3339)}}
			return f
		}(), doctorPass, "1 kinds within budget"},
		{"spool stale", checkFileTelemetry, func() doctorFacts {
			f := steady
			f.st.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: now.Add(-25 * time.Minute)}
			return f
		}(), doctorFail, "spool not written for 25 min"},
		{"service not loaded", checkFileTelemetry, func() doctorFacts {
			f := steady
			f.st.ESService = &collect.ESServiceSnapshot{State: "not-loaded"}
			return f
		}(), doctorFail, "not loaded"},
		{"flooding writer", checkFileTelemetry, func() doctorFacts {
			f := steady
			f.st.ESService = &collect.ESServiceSnapshot{State: "running", Flooding: true}
			return f
		}(), doctorFail, "did not parse"},
		{"unparsed share alone", checkFileTelemetry, func() doctorFacts {
			f := steady
			f.st.ESService = &collect.ESServiceSnapshot{State: "running", UnparsedShare: 0.9}
			return f
		}(), doctorFail, "did not parse"},
		{"low unparsed share is not flooding", checkFileTelemetry, func() doctorFacts {
			f := steady
			f.st.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: now, UnparsedShare: 0.1}
			return f
		}(), doctorPass, "running"},
	}
	for _, tc := range cases {
		state, detail := tc.check(tc.f)
		if state != tc.state || !strings.Contains(detail, tc.has) {
			t.Errorf("%s: %s %q, want %s containing %q", tc.name, state, detail, tc.state, tc.has)
		}
	}
}

func TestDoctorHermes(t *testing.T) {
	polled := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		st            *collect.HermesStatus
		state, detail string
	}{
		"unwired": {nil, doctorSkip, "not wired"},
		"absent":  {&collect.HermesStatus{Root: "/h", LastPoll: polled}, doctorSkip, "not installed (no state.db under /h)"},
		"read": {&collect.HermesStatus{Root: "/h", LastPoll: polled, DBs: []collect.HermesDBStatus{
			{Path: "/h/state.db", Watermark: 42}, {Path: "/h/profiles/w/state.db", Watermark: 3}}},
			doctorPass, "/h/state.db @ message 42, /h/profiles/w/state.db @ message 3 · polled 2026-09-23T08:00:00Z"},
		"failing": {&collect.HermesStatus{Root: "/h", LastPoll: polled, LastError: "/h/state.db: messages: no such table",
			DBs: []collect.HermesDBStatus{{Path: "/h/state.db"}}}, doctorFail, "/h/state.db: messages: no such table"},
	} {
		if state, detail := checkHermes(doctorFacts{hermes: tc.st}); state != tc.state || detail != tc.detail {
			t.Errorf("%s: checkHermes = %s %q, want %s %q", name, state, detail, tc.state, tc.detail)
		}
	}

	// Wired through Deps, the report carries the row with its fix on fail.
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	t.Setenv("HOME", t.TempDir())
	a := New(Deps{Store: st, Status: func() Status { return Status{Uptime: "1h0m0s"} },
		Hermes: func() collect.HermesStatus { return collect.HermesStatus{Root: "/h", LastError: "boom"} }})
	if c := doctorCheckByID(t, a.doctorReport(polled), "hermes"); c.State != doctorFail || c.Detail != "boom" || c.Fix == "" {
		t.Fatalf("hermes check = %+v, want fail with a fix", c)
	}
}
