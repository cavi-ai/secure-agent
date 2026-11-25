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
	"github.com/cavi-ai/secure-agent/daemon/internal/doctor"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// getDoctor serves GET /doctor against st with a fixed status. HOME is
// hermetic so the hook-registration check never reads a real settings file.
func getDoctor(t *testing.T, st *store.Store, status Status) (DoctorReport, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	a := newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: func() Status { return status }})
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
	probeIDs := doctor.ProbeIDs()
	if len(rep.Checks) != len(probeIDs) {
		t.Fatalf("got %d checks, want %d", len(rep.Checks), len(probeIDs))
	}
	var sum DoctorSummary
	for i, c := range rep.Checks {
		if c.ID != probeIDs[i] {
			t.Fatalf("check %d = %q, want %q (fixed order)", i, c.ID, probeIDs[i])
		}
		switch c.State {
		case doctor.Pass:
			sum.Pass++
		case doctor.Fail:
			sum.Fail++
		case doctor.Skip:
			sum.Skip++
		default:
			t.Fatalf("check %s state %q", c.ID, c.State)
		}
		if (c.State == doctor.Fail) != (c.Fix != "") && c.ID != "bus" {
			t.Fatalf("check %s: fix %q must be set exactly on fail", c.ID, c.Fix)
		}
	}
	if rep.Summary != sum {
		t.Fatalf("summary %+v, counted %+v", rep.Summary, sum)
	}
	for id, want := range map[string]string{
		"hook-active":      doctor.Skip,
		"tool-pairing":     doctor.Pass,
		"session-identity": doctor.Skip,
		"hook-registered":  doctor.Skip, // no Claude process; its registration is irrelevant
		"file-telemetry":   doctor.Skip,
		"egress-routing":   doctor.Pass,
		"bus":              doctor.Pass,
	} {
		if c := doctorCheckByID(t, rep, id); c.State != want {
			t.Errorf("%s = %s (%s), want %s", id, c.State, c.Detail, want)
		}
	}
	if c := doctorCheckByID(t, rep, "hook-registered"); c.Fix != "" {
		t.Errorf("hook-registered fix = %q", c.Fix)
	}

	rec := httptest.NewRecorder()
	newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: func() Status { return Status{} }}).buildMux().
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
		if c := doctorCheckByID(t, rep, id); c.State != doctor.Skip || c.Detail != doctor.GraceDetail {
			t.Errorf("%s = %s (%q), want skip inside the boot window", id, c.State, c.Detail)
		}
	}
	if c := doctorCheckByID(t, rep, "file-telemetry"); c.State != doctor.Pass {
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
	if c.State != doctor.Fail || !strings.Contains(c.Detail, "1 duplicate") || c.Fix == "" {
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
	if c.State != doctor.Fail || !strings.Contains(c.Detail, "spawn scheduled") || !strings.Contains(c.Fix, "Full Disk Access") {
		t.Fatalf("file-telemetry = %+v, want fail with the service state and the FDA fix", c)
	}
}

func TestDoctorFileTelemetryRefusedSpawnNamesReregister(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s",
		ESService: &collect.ESServiceSnapshot{State: "spawn scheduled (last exit 78: EX_CONFIG)", SpoolMtime: time.Now().Add(-8 * time.Minute)}})
	c := doctorCheckByID(t, rep, "file-telemetry")
	if c.State != doctor.Fail || !strings.Contains(c.Detail, "78: EX_CONFIG") || !strings.Contains(c.Detail, "Re-register") {
		t.Fatalf("file-telemetry = %+v, want fail naming the exit code and Re-register", c)
	}
}

func TestDoctorFileTelemetryFailsOnFlood(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s",
		ESService: &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), Flooding: true, UnparsedShare: 0.97, BytesSkipped: 6 << 20}})
	c := doctorCheckByID(t, rep, "file-telemetry")
	if c.State != doctor.Fail || !strings.Contains(c.Detail, "did not parse") ||
		!strings.Contains(c.Fix, "Reinstall the file telemetry helper from the Setup card") {
		t.Fatalf("file-telemetry = %+v, want fail naming the unparsed share with the reinstall fix", c)
	}
}

// A flood verdict from a spool nobody writes any more does not mask a
// service that is not loaded.
func TestDoctorFileTelemetryStaleFloodReportsNotLoaded(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s",
		ESService: &collect.ESServiceSnapshot{State: "not-loaded", SpoolMtime: time.Now().Add(-10 * time.Minute), Flooding: true, UnparsedShare: 0.99}})
	if c := doctorCheckByID(t, rep, "file-telemetry"); c.State != doctor.Fail || c.Detail != "root service not loaded" {
		t.Fatalf("file-telemetry = %+v, want fail: root service not loaded", c)
	}
}

func TestDoctorHookActivityAbsenceIsNotFailure(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	status := Status{Running: true, Uptime: "1h0m0s", ActiveAgents: 3, Agents: []AgentSummary{{PID: 42, Name: "claude"}}}
	rep, _ := getDoctor(t, st, status)
	c := doctorCheckByID(t, rep, "hook-active")
	if c.State != doctor.Skip || !strings.Contains(c.Detail, "claude") || c.Fix != "" {
		t.Fatalf("hook-active = %+v, absent observations must stay neutral", c)
	}

	st.UpsertSession(model.Session{ID: "claude-session", Harness: "claude", StartedAt: time.Now(), LastSeenAt: time.Now()})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: time.Now(), SessionID: "claude-session", Detail: "Bash"})
	rep, _ = getDoctor(t, st, status)
	if c := doctorCheckByID(t, rep, "hook-active"); c.State != doctor.Pass || c.Detail != "recent attributed hook activity: claude" {
		t.Fatalf("hook-active after a hook event = %+v, want pass", c)
	}
}

func TestDoctorEgressAndBusFail(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", ProxyEnabled: true, UninspectedEgress: 5, BusDrops: 7, BusDropping: true})
	if c := doctorCheckByID(t, rep, "egress-routing"); c.State != doctor.Fail || !strings.Contains(c.Detail, "5") || !strings.Contains(c.Fix, "agent-env.sh") || !strings.Contains(c.Fix, "Protection → Traffic") {
		t.Fatalf("egress-routing = %+v, want fail with the count and the routing fix", c)
	}
	if c := doctorCheckByID(t, rep, "bus"); c.State != doctor.Fail || !strings.Contains(c.Detail, "7") || !strings.Contains(c.Fix, "cannot recover") {
		t.Fatalf("bus = %+v, want fail with the count and honest recovery guidance", c)
	}
}

// Drops that stopped more than the loss window ago pass and are named.
func TestDoctorBusPassesOnceDropsStop(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	last := time.Now().Add(-collect.LossWindow - time.Minute)
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", BusDrops: 7, BusDropAt: &last})
	if c := doctorCheckByID(t, rep, "bus"); c.State != doctor.Pass || !strings.Contains(c.Detail, "7 subscriber deliveries dropped") || !strings.Contains(c.Detail, "none since") {
		t.Fatalf("bus = %+v, want pass naming the earlier drops", c)
	}
}

func TestDoctorHermes(t *testing.T) {
	polled := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		st            *collect.HermesStatus
		state, detail string
	}{
		"unwired": {nil, doctor.Skip, "not wired"},
		"absent":  {&collect.HermesStatus{Root: "/h", LastPoll: polled}, doctor.Skip, "state.db not found under /h; set hermes_home or export HERMES_STATE_DIR/HERMES_HOME in the daemon's environment or login shell"},
		"read": {&collect.HermesStatus{Root: "/h", LastPoll: polled, DBs: []collect.HermesDBStatus{
			{Path: "/h/state.db", Watermark: 42}, {Path: "/h/profiles/w/state.db", Watermark: 3}}},
			doctor.Pass, "/h/state.db @ message 42, /h/profiles/w/state.db @ message 3 · polled 2026-09-23T08:00:00Z"},
		"failing": {&collect.HermesStatus{Root: "/h", LastPoll: polled, LastError: "/h/state.db: messages: no such table",
			DBs: []collect.HermesDBStatus{{Path: "/h/state.db"}}}, doctor.Fail, "/h/state.db: messages: no such table"},
	} {
		if state, detail := doctor.CheckHermes(doctor.Facts{Hermes: tc.st}); state != tc.state || detail != tc.detail {
			t.Errorf("%s: checkHermes = %s %q, want %s %q", name, state, detail, tc.state, tc.detail)
		}
	}

	// Wired through Deps, the report carries the row with its fix on fail.
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	t.Setenv("HOME", t.TempDir())
	a := New(Deps{Store: st, Status: func() Status { return Status{Uptime: "1h0m0s"} },
		Doctor: DoctorDeps{Hermes: func() collect.HermesStatus { return collect.HermesStatus{Root: "/h", LastError: "boom"} }}})
	if c := doctorCheckByID(t, a.doctorReport(polled), "hermes"); c.State != doctor.Fail || c.Detail != "boom" || c.Fix == "" {
		t.Fatalf("hermes check = %+v, want fail with a fix", c)
	}
}

// launchd keeps the last exit code of a service it restarted. A running
// service with an earlier exit is up and writing, not failing; one that stops
// writing still fails on the spool's age.
func TestDoctorFileTelemetryRunningAfterAnEarlierExit(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", ActiveAgents: 2,
		ESService: &collect.ESServiceSnapshot{State: "running (last exit 1)", SpoolMtime: time.Now(), SpoolSize: 1 << 20}})
	if c := doctorCheckByID(t, rep, "file-telemetry"); c.State != doctor.Pass {
		t.Fatalf("file-telemetry = %+v, want pass: the service is running and the spool is fresh", c)
	}
	rep, _ = getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", ActiveAgents: 2,
		ESService: &collect.ESServiceSnapshot{State: "running (last exit 1)", SpoolMtime: time.Now().Add(-time.Hour), SpoolSize: 1 << 20}})
	if c := doctorCheckByID(t, rep, "file-telemetry"); c.State != doctor.Fail || !strings.Contains(c.Detail, "spool not written") {
		t.Fatalf("file-telemetry = %+v, want fail: running but the spool is an hour old", c)
	}
	rep, _ = getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s",
		ESService: &collect.ESServiceSnapshot{State: "spawn scheduled (last exit 1)"}})
	if c := doctorCheckByID(t, rep, "file-telemetry"); c.State != doctor.Fail || !strings.Contains(c.Detail, "spawn scheduled") {
		t.Fatalf("file-telemetry = %+v, want fail: crash loop", c)
	}
}

// Routed traffic is the proof the proxy is in the path: the pass names how
// many connections it served and how many it decrypted.
func TestDoctorEgressRoutedCounts(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h0m0s", ProxyEnabled: true, ProxyTunneled: 12, ProxyDecrypted: 3})
	if c := doctorCheckByID(t, rep, "egress-routing"); c.State != doctor.Pass || !strings.Contains(c.Detail, "15 connections since start (3 decrypted)") {
		t.Fatalf("egress-routing = %+v, want pass naming 15 connections, 3 decrypted", c)
	}
}

// A spool loss fails Doctor and posture while it grows; once it stops, the
// check passes and names the earlier loss.
func TestDoctorSpoolLossFailsOnlyWhileGrowing(t *testing.T) {
	earlier := time.Now().Add(-collect.LossWindow - time.Minute)
	quiet := collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), BytesLost: 123, LostAt: &earlier}
	if state, detail := doctor.CheckFileTelemetry(doctor.Facts{Status: posture.Status{ESService: &quiet}, Now: time.Now()}); state != doctor.Pass || !strings.Contains(detail, "123 unread spool bytes lost at") || !strings.Contains(detail, "none since") {
		t.Fatalf("quiet loss: state=%s detail=%s, want pass naming the loss", state, detail)
	}
	if items := posture.ESServiceItems(time.Now(), quiet); len(items) != 0 {
		t.Fatalf("quiet loss posture items = %+v, want none", items)
	}

	now := time.Now()
	es := collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), BytesLost: 123, LostAt: &now, Losing: true}
	state, detail := doctor.CheckFileTelemetry(doctor.Facts{Status: posture.Status{ESService: &es}, Now: time.Now()})
	if state != doctor.Fail || !strings.Contains(detail, "123 unread spool bytes") {
		t.Fatalf("state=%s detail=%s", state, detail)
	}
	items := posture.ESServiceItems(time.Now(), es)
	if len(items) != 1 || items[0].Severity != 2 || !strings.Contains(items[0].Detail, "123 unread spool bytes") {
		t.Fatalf("items=%+v", items)
	}
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	rep, _ := getDoctor(t, st, Status{Running: true, Uptime: "1h", ESService: &es})
	check := doctorCheckByID(t, rep, "file-telemetry")
	if !strings.Contains(check.Fix, "cannot recover overwritten evidence") {
		t.Fatalf("incorrect loss recovery guidance: %+v", check)
	}
}
