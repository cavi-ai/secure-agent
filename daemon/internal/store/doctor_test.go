package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// seedDoctorStore: `since` is one hour ago. Sessions and events on both
// sides of it, named and unnamed, with and without workspace and repo.
func seedDoctorStore(t *testing.T, now time.Time) *Store {
	t.Helper()
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, sess := range []struct {
		model.Session
		ago time.Duration
	}{
		{model.Session{ID: "a", Harness: "claude", Workspace: "/w/a", Repo: "A"}, 10 * time.Minute},
		{model.Session{ID: "b", Harness: "codex", Workspace: "/w/b"}, 5 * time.Minute},
		{model.Session{ID: "c", Harness: "claude"}, 2 * time.Minute},
		{model.Session{ID: "d", Workspace: "/w/d", Repo: "D"}, time.Minute},
		{model.Session{ID: "e", Harness: "claude", Workspace: "/w/e", Repo: "E"}, 3 * time.Hour},
	} {
		sess.StartedAt, sess.LastSeenAt, sess.Status = now.Add(-sess.ago), now, model.SessionActive
		s.UpsertSession(sess.Session)
	}
	put := func(e event.Event, ago time.Duration) {
		e.TS = now.Add(-ago)
		s.PutEvent(e)
	}
	put(event.Event{Kind: event.KindPluginAction, Detail: "Bash"}, 30*time.Minute)
	put(event.Event{Kind: event.KindPluginAction, Detail: "Bash"}, 2*time.Hour)

	// One paired call (start + completion fold into one row), one id-less
	// call since `since`, one id-less call before it.
	put(event.Event{Kind: event.KindToolCall, SessionID: "a", CallID: "c1", ToolName: "Bash", ToolStatus: "running"}, 10*time.Minute)
	put(event.Event{Kind: event.KindToolCall, SessionID: "a", CallID: "c1", ToolName: "Bash", ToolStatus: "ok"}, 9*time.Minute)
	put(event.Event{Kind: event.KindToolCall, SessionID: "a", ToolName: "Read"}, 5*time.Minute)
	put(event.Event{Kind: event.KindToolCall, SessionID: "a", ToolName: "Read"}, 2*time.Hour)
	// A duplicate (session_id, call_id) pair: rows with a NULL session id are
	// distinct under the unique call index, so a legacy writer could store it.
	for i := 0; i < 2; i++ {
		if _, err := s.db.Exec(`INSERT INTO events (kind, ts, session_id, call_id) VALUES (?, ?, NULL, 'dup')`,
			int(event.KindToolCall), now.Add(-3*time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}

	put(event.Event{Kind: event.KindModelCall, SessionID: "a", Model: "claude-sonnet-4", CostUSD: 0.5}, 10*time.Minute)
	put(event.Event{Kind: event.KindModelCall, SessionID: "b", Model: "claude-opus-4"}, 9*time.Minute)
	put(event.Event{Kind: event.KindModelCall, SessionID: "a", Model: "gpt-5"}, 8*time.Minute)
	put(event.Event{Kind: event.KindModelCall, SessionID: "b", Model: "gpt-5", CostUSD: 0.2}, 7*time.Minute)
	put(event.Event{Kind: event.KindTurn, SessionID: "c"}, time.Minute)
	for i := 0; i < 3; i++ {
		put(event.Event{Kind: event.KindFileOpen, Path: "/tmp/x"}, time.Duration(i)*time.Minute)
	}
	put(event.Event{Kind: event.Kind(99)}, time.Minute)
	return s
}

func TestDoctorSessionStats(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := seedDoctorStore(t, now)
	since := now.Add(-time.Hour)

	total, named, withWS, withRepo := s.SessionIdentityStats(since)
	if total != 5 || named != 4 || withWS != 2 || withRepo != 1 {
		t.Fatalf("SessionIdentityStats = total %d named %d withWorkspace %d withRepo %d, want 5 4 2 1", total, named, withWS, withRepo)
	}
	if n := s.SessionsCreatedSince(since); n != 4 {
		t.Fatalf("SessionsCreatedSince = %d, want 4 (e started before since)", n)
	}
	byHarness := s.SessionsByHarness(since)
	if len(byHarness) != 2 || byHarness["claude"] != 2 || byHarness["codex"] != 1 {
		t.Fatalf("SessionsByHarness = %v, want claude 2, codex 1 (unnamed and pre-since excluded)", byHarness)
	}
}

func TestDoctorEventStats(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := seedDoctorStore(t, now)
	since := now.Add(-time.Hour)

	if dupes, idless := s.ToolCallStats(since); dupes != 1 || idless != 1 {
		t.Fatalf("ToolCallStats = dupes %d idless %d, want 1 1", dupes, idless)
	}
	if cp, cu, au, all := s.PricingStats(); cp != 1 || cu != 1 || au != 2 || all != 4 {
		t.Fatalf("PricingStats = %d %d %d %d, want claudePriced 1, claudeUnpriced 1, allUnpriced 2, allCalls 4", cp, cu, au, all)
	}
	if n := s.HookEventsSince(since); n != 1 {
		t.Fatalf("HookEventsSince(1h) = %d, want 1", n)
	}
	if n := s.HookEventsSince(now.Add(-3 * time.Hour)); n != 2 {
		t.Fatalf("HookEventsSince(3h) = %d, want 2", n)
	}
	// claude: a's paired call, a's id-less call, a's two model calls, c's
	// turn; codex: b's two model calls. Pre-since and session-less rows drop.
	trace := s.TraceRowsByHarness(since)
	if len(trace) != 2 || trace["claude"] != 5 || trace["codex"] != 2 {
		t.Fatalf("TraceRowsByHarness = %v, want claude 5, codex 2", trace)
	}
}

func TestDoctorRetentionReport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := seedDoctorStore(t, now)

	rep := s.RetentionReport()
	wantRows := map[int]int{
		int(event.KindFileOpen): 3, int(event.KindPluginAction): 2, int(event.KindToolCall): 5,
		int(event.KindTurn): 1, int(event.KindModelCall): 4, 99: 1,
	}
	if len(rep) != len(wantRows) {
		t.Fatalf("RetentionReport = %+v, want one row per kind present (%d)", rep, len(wantRows))
	}
	for i, r := range rep {
		if i > 0 && rep[i-1].Kind >= r.Kind {
			t.Fatalf("not ordered by kind: %+v", rep)
		}
		if r.Rows != wantRows[r.Kind] {
			t.Errorf("kind %d rows = %d, want %d", r.Kind, r.Rows, wantRows[r.Kind])
		}
		if r.Name != event.Kind(r.Kind).String() {
			t.Errorf("kind %d name = %q", r.Kind, r.Name)
		}
		want, listed := kindBudgets[r.Kind]
		if !listed {
			want = defaultKindBudget
		}
		if r.Budget != want {
			t.Errorf("kind %d budget = %d, want %d", r.Kind, r.Budget, want)
		}
	}
	for _, r := range rep {
		if r.Kind == int(event.KindPluginAction) {
			if want := now.Add(-2 * time.Hour).Format(time.RFC3339); r.OldestTS != want {
				t.Fatalf("plugin-action oldest = %q, want %q", r.OldestTS, want)
			}
		}
		if r.Kind == 99 && (r.Name != "unknown" || r.Budget != defaultKindBudget) {
			t.Fatalf("unlisted kind = %+v, want name unknown and the default budget", r)
		}
	}

	empty, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if r := empty.RetentionReport(); r == nil || len(r) != 0 {
		t.Fatalf("empty store RetentionReport = %#v, want non-nil empty", r)
	}
}

// Trace coverage counts sessions SEEN since boot at transcript or hook
// confidence, whatever their start: a backfilled conversation started days ago
// and active now counts; a process-tree guess and a stale row do not.
func TestSessionsSeenByHarness(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Second)
	since := now.Add(-time.Hour)
	for _, sess := range []model.Session{
		{ID: "a", Harness: "codex", Confidence: model.ConfTranscript, StartedAt: now, LastSeenAt: now},
		{ID: "b", Harness: "openclaw", Confidence: model.ConfTranscript, StartedAt: now.Add(-48 * time.Hour), LastSeenAt: now},
		{ID: "c", Harness: "claude", Confidence: model.ConfHook, StartedAt: now.Add(-3 * time.Hour), LastSeenAt: now.Add(-time.Minute)},
		{ID: "d", Harness: "codex", Confidence: model.ConfProcessTree, StartedAt: now, LastSeenAt: now},
		{ID: "e", Harness: "codex", Confidence: model.ConfTranscript, StartedAt: now.Add(-3 * time.Hour), LastSeenAt: now.Add(-2 * time.Hour)},
		{ID: "f", Confidence: model.ConfTranscript, StartedAt: now, LastSeenAt: now},
		{ID: "g", Harness: "hermes", Confidence: model.ConfTranscript, StartedAt: now.Add(-48 * time.Hour), LastSeenAt: now.Add(-47 * time.Hour)},
		{ID: "h", Harness: "hermes", Confidence: model.ConfTranscript, StartedAt: now.Add(-48 * time.Hour), LastSeenAt: now.Add(-47 * time.Hour)},
	} {
		s.UpsertSession(sess)
	}
	// g is only closed since: ending moves last_seen_at, but it is no activity.
	s.EndSession("g", now)
	// h ran since and then ended.
	s.PutEvent(event.Event{Kind: event.KindModelCall, SessionID: "h", TS: now.Add(-time.Minute)})
	s.EndSession("h", now)
	got := s.SessionsSeenByHarness(since)
	if len(got) != 4 || got["codex"] != 1 || got["openclaw"] != 1 || got["claude"] != 1 || got["hermes"] != 1 {
		t.Fatalf("SessionsSeenByHarness = %v, want codex 1, openclaw 1, claude 1, hermes 1 (h, not g)", got)
	}
}
