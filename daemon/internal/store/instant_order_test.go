package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
)

// guard_decisions.at is written fixed-width UTC, so its text order is its
// instant order; it is not listed.
var (
	sqliteDateFunc = regexp.MustCompile(`(?i)\b(datetime|julianday|strftime|unixepoch|date|time)\s*\(`)
	timestampCols  = `(ts|created_at|started_at|root_started_at|ended_at|last_seen_at|last_seen|first_seen|closed_at|revoked_at|resolved_at|acknowledged_at|requested_at|captured_at|last_flag_at|saved_at|expires_at|repeat_at|finished_at|reported_at|generated_at)`
	rawInstantSQL  = regexp.MustCompile(`(?i)((ORDER BY|MIN\(|MAX\()\s*([a-z]+\.)?` + timestampCols + `\b|\b([a-z]+\.)?` + timestampCols + `\s*(<|>|<=|>=)\s*[?:a-z])`)
)

// Persisted timestamps vary in fractional width and UTC offset, so SQL
// compares, orders and buckets them only through timestamps.go.
func TestStoreSQLComparesInstantsThroughTimestamps(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || file == "timestamps.go" {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, re := range []*regexp.Regexp{sqliteDateFunc, rawInstantSQL} {
				if m := re.FindString(text); m != "" {
					t.Errorf("%s: SQL %q bypasses timestamps.go", fset.Position(lit.Pos()), m)
				}
			}
			return true
		})
	}
}

// subsecond is a cutoff with a fractional second; offsetStamp stores an
// instant the way a legacy local-offset writer did.
var subsecond = time.Date(2026, 10, 11, 12, 0, 0, 500_000_000, time.UTC)

func offsetStamp(at time.Time) string {
	return at.In(time.FixedZone("east", 5*60*60+45*60)).Format(time.RFC3339Nano)
}

func restamp(t *testing.T, s *Store, query string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestRuleCountsHonorSubsecondWindow(t *testing.T) {
	s := labelStore(t)
	now := subsecond.Add(7 * 24 * time.Hour)
	for id, at := range map[string]time.Time{"before": subsecond.Add(-time.Nanosecond), "at": subsecond, "after": subsecond.Add(time.Nanosecond)} {
		if _, err := s.PutFlag(model.Flag{ID: id, Rule: "keychain-access", Severity: 3, Agent: "codex", TS: at}); err != nil {
			t.Fatal(err)
		}
		restamp(t, s, `UPDATE flags SET ts=? WHERE id=?`, offsetStamp(at), id)
	}
	last7, last30, err := s.RuleCounts("keychain-access", "codex", now)
	if err != nil || last7 != 2 || last30 != 3 {
		t.Fatalf("RuleCounts = %d, %d, %v; want 2, 3", last7, last30, err)
	}
}

func TestDoctorCountsHonorSubsecondSince(t *testing.T) {
	s := activityStore(t)
	for id, at := range map[string]time.Time{"before": subsecond.Add(-time.Nanosecond), "at": subsecond, "after": subsecond.Add(time.Nanosecond)} {
		if err := s.UpsertSession(model.Session{ID: id, Harness: "claude", Workspace: "/w/" + id, Repo: "R", StartedAt: at, LastSeenAt: at, Status: model.SessionActive}); err != nil {
			t.Fatal(err)
		}
		restamp(t, s, `UPDATE sessions SET started_at=? WHERE id=?`, offsetStamp(at), id)
		for _, e := range []event.Event{{Kind: event.KindPluginAction, Detail: id}, {Kind: event.KindToolCall, SessionID: id, ToolName: "Read"}} {
			e.TS = at
			if _, err := s.PutEvent(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	restamp(t, s, `UPDATE events SET ts=? WHERE ts=?`, offsetStamp(subsecond.Add(-time.Nanosecond)), subsecond.Add(-time.Nanosecond).Format(time.RFC3339Nano))

	if n := s.SessionsCreatedSince(subsecond); n != 2 {
		t.Errorf("SessionsCreatedSince = %d, want 2", n)
	}
	if n := s.HookEventsSince(subsecond); n != 2 {
		t.Errorf("HookEventsSince = %d, want 2", n)
	}
	if _, idless := s.ToolCallStats(subsecond); idless != 2 {
		t.Errorf("ToolCallStats idless = %d, want 2", idless)
	}
	if got := s.SessionsByHarness(subsecond); got["claude"] != 2 {
		t.Errorf("SessionsByHarness = %v, want claude:2", got)
	}
	if _, _, withWorkspace, withRepo := s.SessionIdentityStats(subsecond); withWorkspace != 2 || withRepo != 2 {
		t.Errorf("SessionIdentityStats workspace=%d repo=%d, want 2, 2", withWorkspace, withRepo)
	}
}

func TestDoctorWorkspaceReposOrderByInstant(t *testing.T) {
	s := activityStore(t)
	for id, at := range map[string]time.Time{"a-later": subsecond.Add(2 * time.Nanosecond), "b-earlier": subsecond.Add(time.Nanosecond)} {
		if err := s.UpsertSession(model.Session{ID: id, Harness: "claude", Workspace: "/w/" + id, StartedAt: at, LastSeenAt: at, Status: model.SessionActive}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.DoctorWorkspaceRepos(subsecond)
	if err != nil || len(got) != 2 || got[0][0] != "/w/b-earlier" || got[1][0] != "/w/a-later" {
		t.Fatalf("DoctorWorkspaceRepos = %v, %v; want b-earlier then a-later", got, err)
	}
}

func TestCostReportHonorsSubsecondWindow(t *testing.T) {
	s := activityStore(t)
	until := subsecond.Add(time.Hour)
	for at, cost := range map[time.Time]float64{subsecond.Add(-time.Nanosecond): 1, subsecond: 2, until.Add(-time.Nanosecond): 4, until: 8} {
		if _, err := s.PutEvent(event.Event{Kind: event.KindModelCall, TS: at, Model: "claude-sonnet-4", CostUSD: cost}); err != nil {
			t.Fatal(err)
		}
	}
	rep := s.CostReport(subsecond, until, "repo", CostOptions{})
	if rep.Total.Calls != 2 || rep.Total.CostUSD != 6 {
		t.Fatalf("CostReport total = %d calls $%v, want 2 calls $6", rep.Total.Calls, rep.Total.CostUSD)
	}
}

func TestAdvisorBackfillHonorsSubsecondSinceAndOffsets(t *testing.T) {
	s := labelStore(t)
	for id, at := range map[string]time.Time{
		"before":       subsecond.Add(-time.Nanosecond),
		"newer-utc":    subsecond.Add(400 * time.Millisecond),
		"older-offset": subsecond.Add(100 * time.Millisecond),
	} {
		if _, err := s.PutFlag(model.Flag{ID: id, Rule: "keychain-access", Severity: 3, Agent: "codex", TS: at}); err != nil {
			t.Fatal(err)
		}
		if id != "newer-utc" {
			restamp(t, s, `UPDATE flags SET ts=? WHERE id=?`, offsetStamp(at), id)
		}
	}
	flags := testutil.Read[[]model.Flag](t)(s.CriticalFlagsMissingAdvisor(subsecond, 10))
	if len(flags) != 2 || flags[0].ID != "newer-utc" || flags[1].ID != "older-offset" {
		t.Fatalf("backfill = %v, want newer-utc then older-offset", flagIDs(flags))
	}
}

func flagIDs(flags []model.Flag) []string {
	ids := make([]string, len(flags))
	for i, f := range flags {
		ids[i] = f.ID
	}
	return ids
}

func TestPathFindingsNewestFirstAcrossFractionWidths(t *testing.T) {
	s := fileTestStore(t)
	path := "/w/secret.env"
	whole := subsecond.Truncate(time.Second)
	for id, at := range map[string]time.Time{"whole-second": whole, "half-second": whole.Add(500 * time.Millisecond)} {
		s.PutFlag(model.Flag{ID: id, Rule: "secret-in-transcript", Severity: 3, TS: at, Agent: "codex",
			Evidence: []model.EvidenceItem{{Kind: "transcript", Label: path, Rule: "fp-1"}}})
	}
	got := testutil.Read[[]model.FileFinding](t)(s.PathFindings(path, 1))
	if len(got) != 1 || got[0].ID != "half-second" {
		t.Fatalf("PathFindings = %+v, want half-second first", got)
	}
}

func TestHostFirstSeenAcrossFractionWidths(t *testing.T) {
	s := activityStore(t)
	whole := subsecond.Truncate(time.Second)
	for _, at := range []time.Time{whole.Add(500 * time.Millisecond), whole} {
		if _, err := s.PutEvent(event.Event{Kind: event.KindConnOpen, TS: at, RemoteHost: "api.example.test", RemotePort: 443}); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.TrendFor("egress-new-host", "api.example.test").HostFirstSeen; got != whole.Format(time.RFC3339Nano) {
		t.Fatalf("HostFirstSeen = %q, want %q", got, whole.Format(time.RFC3339Nano))
	}
}

func TestStaleRunningSweepHonorsFractionWidths(t *testing.T) {
	s := activityStore(t)
	cutoff := subsecond.Truncate(time.Second)
	if _, err := s.PutEvent(event.Event{Kind: event.KindToolCall, TS: cutoff.Add(500 * time.Millisecond), SessionID: "s", CallID: "c", ToolName: "Bash", ToolStatus: "running"}); err != nil {
		t.Fatal(err)
	}
	if n := s.SweepStaleRunningCalls(cutoff); n != 0 {
		t.Fatalf("SweepStaleRunningCalls swept %d calls started after the cutoff", n)
	}
}

func TestCleanupTotalsHonorFractionWidths(t *testing.T) {
	s := activityStore(t)
	now := subsecond.Truncate(time.Second).Add(30 * 24 * time.Hour)
	s.PutCleanup(model.CleanupEntry{TS: now.Add(-30*24*time.Hour + 500*time.Millisecond), Action: "worktree-remove", Path: "/w/x", Bytes: 7})
	if got, err := s.CleanupTotals(now); err != nil || got.Count30d != 1 || got.Bytes30d != 7 {
		t.Fatalf("CleanupTotals 30d = %d rows %d bytes, want 1 row 7 bytes", got.Count30d, got.Bytes30d)
	}
}

func TestSessionReportEventsOrderBySubmillisecondTime(t *testing.T) {
	s := activityStore(t)
	for _, at := range []time.Time{subsecond.Add(2 * time.Microsecond), subsecond.Add(time.Microsecond)} {
		if _, err := s.PutEvent(event.Event{Kind: event.KindTurn, TS: at, SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.sessionEventsOldestFirst("s")
	if err != nil || len(events) != 2 || !events[0].TS.Before(events[1].TS) {
		t.Fatalf("sessionEventsOldestFirst = %v, %v; want oldest first", events, err)
	}
}

func TestSessionMemorySkipsUnplaceableTimestamps(t *testing.T) {
	s := activityStore(t)
	now := time.Now().UTC()
	for i, at := range []time.Time{now.Add(-time.Minute), now.Add(-2 * time.Minute)} {
		if _, err := s.PutEvent(event.Event{Kind: event.KindToolCall, TS: at, SessionID: "s", CallID: string(rune('a' + i)), ToolName: "Read"}); err != nil {
			t.Fatal(err)
		}
	}
	restamp(t, s, `UPDATE events SET ts=? WHERE call_id='b'`, now.Add(-2*time.Minute).Format(time.DateTime))
	facts, _, err := s.QuerySessionMemory("s", nil, 10)
	if err != nil || len(facts) != 1 {
		t.Fatalf("QuerySessionMemory = %d facts, %v; want the one placeable event", len(facts), err)
	}
}

func TestRecentInterventionsNewestFirstAcrossFractionWidths(t *testing.T) {
	s := interventionTestStore(t)
	whole := subsecond.Truncate(time.Second)
	for id, at := range map[string]time.Time{"b-whole": whole, "a-half": whole.Add(500 * time.Millisecond)} {
		r := model.InterventionReceipt{ID: id, SessionKey: "family", Revision: 1, Kind: "terminate", RequestedAt: at, Status: "requested", Verification: "unknown"}
		if ok, err := s.ReserveIntervention(r); err != nil || !ok {
			t.Fatalf("reserve %s: %v %v", id, ok, err)
		}
	}
	rows, err := s.RecentInterventions("", 1)
	if err != nil || len(rows) != 1 || rows[0].ID != "a-half" {
		t.Fatalf("RecentInterventions = %+v, %v; want a-half first", rows, err)
	}
}

func TestWorkspaceActivityLastSeenAcrossFractionWidths(t *testing.T) {
	s := activityStore(t)
	whole := subsecond.Truncate(time.Second)
	for id, at := range map[string]time.Time{"whole": whole, "half": whole.Add(500 * time.Millisecond)} {
		if err := s.UpsertSession(model.Session{ID: id, Workspace: "/w/repo", StartedAt: whole, LastSeenAt: at, Status: model.SessionEnded}); err != nil {
			t.Fatal(err)
		}
	}
	got := s.WorkspaceActivity()
	if len(got) != 1 || !got[0].LastSeen.Equal(whole.Add(500*time.Millisecond)) {
		t.Fatalf("WorkspaceActivity = %+v, want last seen at the half second", got)
	}
}

func TestGuardListsNewestFirstWithinOneSecond(t *testing.T) {
	s := activityStore(t)
	older, newer := offsetStamp(subsecond.Add(100*time.Millisecond)), subsecond.Add(400*time.Millisecond).Format(time.RFC3339Nano)
	for _, path := range []string{"/w/older", "/w/newer"} {
		if err := s.PutGuardPathAllow(GuardPathAllow{Agent: "codex", RuleID: "env-read", Path: path}); err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range []string{"older", "newer"} {
		s.PutGuardRule(GuardRule{Agent: "codex", RuleID: rule, Decision: "allow", Source: "user"})
	}
	restamp(t, s, `UPDATE guard_path_allows SET created_at=CASE path WHEN '/w/older' THEN ? ELSE ? END`, older, newer)
	restamp(t, s, `UPDATE guard_rules SET created_at=CASE rule_id WHEN 'older' THEN ? ELSE ? END`, older, newer)
	if got, err := s.ListGuardPathAllows(1); err != nil || len(got) != 1 || got[0].Path != "/w/newer" {
		t.Errorf("ListGuardPathAllows = %+v, err=%v, want /w/newer first", got, err)
	}
	if got, err := s.ListGuardRules(1); err != nil || len(got) != 1 || got[0].RuleID != "newer" {
		t.Errorf("ListGuardRules = %+v, err=%v, want newer first", got, err)
	}
}

// Range scans gate on SQLite's whole second, so a value without a UTC offset
// matches only outside the bound's second.
func TestInstantRangeGateComparesOffsetlessValuesBySecond(t *testing.T) {
	s := activityStore(t)
	for i, stamp := range []string{"2026-10-11T12:00:01", "2026-10-11T12:00:00.9"} {
		if _, err := s.PutEvent(event.Event{Kind: event.KindPluginAction, TS: subsecond, Detail: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
		restamp(t, s, `UPDATE events SET ts=? WHERE detail=?`, stamp, strconv.Itoa(i))
	}
	if n := s.HookEventsSince(subsecond); n != 1 {
		t.Fatalf("HookEventsSince = %d, want only the later-second offsetless row", n)
	}
}
