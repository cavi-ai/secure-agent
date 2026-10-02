package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

func TestResourceEpisodeSessionIdentity(t *testing.T) {
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Nanosecond)
	cases := []struct {
		name        string
		kind        string
		rootStart   time.Time
		secondStart time.Time
		want        string
	}{
		{name: "exact ended session", rootStart: start, want: "s1"},
		{name: "missing start", want: ""},
		{name: "reused PID", rootStart: start.Add(time.Second), want: ""},
		{name: "ambiguous match", rootStart: start, secondStart: start, want: ""},
		{name: "infrastructure", kind: "infra", rootStart: start, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			st.UpsertSession(model.Session{ID: "s1", Harness: "claude", RootPID: 100, RootStartedAt: start.In(time.FixedZone("offset", -4*3600)).Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: start})
			st.EndSession("s1", time.Now())
			if !tc.secondStart.IsZero() {
				st.UpsertSession(model.Session{ID: "s2", Harness: "claude", RootPID: 100, RootStartedAt: tc.secondStart.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: start})
			}
			key := fmt.Sprintf("100:%d", tc.rootStart.UnixNano())
			episode := resource.Episode{SessionID: "untrusted", CapturedAt: time.Now(), Severity: "warning", Session: resource.Session{Key: key, Kind: tc.kind, RootPID: 100, RootStartedAt: tc.rootStart}}
			if err := st.PutResourceEpisode(episode); err != nil {
				t.Fatal(err)
			}
			var id sql.NullString
			var storedKey, payload string
			if err := st.db.QueryRow(`SELECT session_id, session_key, episode_json FROM resource_episodes`).Scan(&id, &storedKey, &payload); err != nil {
				t.Fatal(err)
			}
			if id.String != tc.want || id.Valid != (tc.want != "") {
				t.Fatalf("session_id=%+v, want %q", id, tc.want)
			}
			if storedKey != key {
				t.Fatalf("family key=%q, want %q", storedKey, key)
			}
			var got resource.Episode
			if err := json.Unmarshal([]byte(payload), &got); err != nil {
				t.Fatal(err)
			}
			if got.SessionID != tc.want {
				t.Fatalf("episode session_id=%q, want %q", got.SessionID, tc.want)
			}
		})
	}
}

func TestLegacyEpisodeExactFamily(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE resource_episodes (id INTEGER PRIMARY KEY AUTOINCREMENT, captured_at TEXT NOT NULL, severity TEXT NOT NULL, session_key TEXT NOT NULL, episode_json TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	key := fmt.Sprintf("100:%d", start.UnixNano())
	if _, err = db.Exec(`INSERT INTO resource_episodes(captured_at,severity,session_key,episode_json) VALUES (?,?,?,?)`, time.Now().Format(time.RFC3339Nano), "warning", key, `{}`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.UpsertSession(model.Session{ID: "s1", RootPID: 100, RootStartedAt: start.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: start})
	var storedID sql.NullString
	if err := st.db.QueryRow(`SELECT session_id FROM resource_episodes WHERE session_key=?`, key).Scan(&storedID); err != nil {
		t.Fatal(err)
	}
	if storedID.Valid {
		t.Fatalf("migration invented attribution: %+v", storedID)
	}
	if got := st.SessionIDForFamilyKey(key); got != "s1" {
		t.Fatalf("exact legacy key resolved to %q", got)
	}
	for _, wrong := range []string{"100:0", fmt.Sprintf("100:%d", start.Add(time.Nanosecond).UnixNano()), fmt.Sprintf("101:%d", start.UnixNano()), "100:bad"} {
		if got := st.SessionIDForFamilyKey(wrong); got != "" {
			t.Fatalf("wrong legacy key %q resolved to %q", wrong, got)
		}
	}
}

func TestRekeySessionRepointsResourceEpisode(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	start := time.Now().UTC().Add(-time.Minute)
	st.UpsertSession(model.Session{ID: "provisional", RootPID: 100, RootStartedAt: start.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: start})
	episode := resource.Episode{CapturedAt: time.Now(), Session: resource.Session{Key: fmt.Sprintf("100:%d", start.UnixNano()), RootPID: 100, RootStartedAt: start}}
	if err := st.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	st.RekeySession("provisional", "canonical")
	var id, payload string
	if err := st.db.QueryRow(`SELECT session_id, episode_json FROM resource_episodes LIMIT 1`).Scan(&id, &payload); err != nil {
		t.Fatal(err)
	}
	if id != "canonical" {
		t.Fatalf("session_id=%q, want canonical", id)
	}
	var got resource.Episode
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "canonical" {
		t.Fatalf("episode_json session_id=%q, want canonical", got.SessionID)
	}
}

func TestConcurrentResourceCaptureAndRekey(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	start := time.Now().UTC().Add(-time.Minute)
	st.UpsertSession(model.Session{ID: "provisional", RootPID: 100, RootStartedAt: start.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: start})
	lookupDone := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	st.resourceEpisodeAfterLookup = func() { close(lookupDone); <-release }
	episode := resource.Episode{CapturedAt: time.Now(), Session: resource.Session{Key: fmt.Sprintf("100:%d", start.UnixNano()), RootPID: 100, RootStartedAt: start}}
	writeDone := make(chan error, 1)
	go func() { writeDone <- st.PutResourceEpisode(episode) }()
	select {
	case <-lookupDone:
	case <-time.After(time.Second):
		t.Fatal("capture did not reach lookup boundary")
	}
	// The identity lock must still be held when capture has chosen its ID.
	if st.mu.TryLock() {
		st.mu.Unlock()
		t.Fatal("capture released identity lock before insert")
	}
	rekeyDone := make(chan struct{})
	go func() { st.RekeySession("provisional", "canonical"); close(rekeyDone) }()
	unblock()
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	<-rekeyDone
	var id, payload string
	if err := st.db.QueryRow(`SELECT session_id, episode_json FROM resource_episodes LIMIT 1`).Scan(&id, &payload); err != nil {
		t.Fatal(err)
	}
	var got resource.Episode
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatal(err)
	}
	if id != "canonical" || got.SessionID != "canonical" {
		t.Fatalf("indexed=%q JSON=%q, want canonical", id, got.SessionID)
	}
}

func TestResourceEpisodeRoundTrip(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	want := resource.Episode{
		CapturedAt: now, Severity: "critical", DiagnosisCodes: []string{"heavy-memory"},
		Host: &resource.HostSnapshot{TotalMemoryBytes: 16 << 30, AvailableMemoryBytes: 2 << 30,
			MemoryPressure: "warning", ThermalState: "nominal", HeadroomScore: 12, Capacity: "critical"},
		Session: resource.Session{Key: "100:1", Name: "claude", Workspace: "/work/app", RootPID: 100,
			RSSBytes: 5 << 30, Processes: []resource.Process{{PID: 100, RSSBytes: 5 << 30}},
			Samples:   []resource.Sample{{At: now, RSSBytes: 5 << 30}},
			Diagnoses: []resource.Diagnosis{{Code: "heavy-memory", Severity: "critical", Summary: "large"}}},
	}
	if err := st.PutResourceEpisode(want); err != nil {
		t.Fatal(err)
	}

	got := st.RecentResourceEpisodes(10)
	if len(got) != 1 {
		t.Fatalf("episodes=%d want 1", len(got))
	}
	if got[0].ID == 0 || !got[0].CapturedAt.Equal(now) || got[0].Session.Workspace != "/work/app" || got[0].Session.Processes[0].PID != 100 || got[0].Host == nil || got[0].Host.AvailableMemoryBytes != 2<<30 {
		t.Fatalf("episode=%+v", got[0])
	}
}

func TestTruncateResourceActivityPreservesUTF8(t *testing.T) {
	got := truncateResourceActivity(strings.Repeat("🤖", 200), 160)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated summary is not valid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 161 {
		t.Fatalf("runes=%d want 161 including ellipsis", utf8.RuneCountInString(got))
	}
}

func TestResourceEpisodeCapturesOnlyFamilyActivityInsidePrelude(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	st.PutEvent(event.Event{Kind: event.KindFileWrite, TS: now.Add(-9 * time.Second), PID: 101, Path: "/tmp/recycled-pid"})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(-7 * time.Second), PID: 101, Detail: "Bash tool ran"})
	st.PutEvent(event.Event{Kind: event.KindConnOpen, TS: now.Add(-6 * time.Second), PID: 101, RemoteHost: "api.example.com", RemotePort: 443})
	st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now.Add(-4 * time.Second), PID: 101, Path: "/Users/alice/private/project/.env"})
	st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now.Add(-5 * time.Second), PID: 999, Path: "/private/unrelated/.env"})
	st.PutEvent(event.Event{Kind: event.KindExec, TS: now.Add(100 * time.Millisecond), PID: 101, ExePath: "/usr/bin/node"})
	for i := 0; i < 90; i++ {
		st.PutEvent(event.Event{Kind: event.KindExec, TS: now.Add(200*time.Millisecond + time.Duration(i)), PID: 101, ExePath: "/usr/bin/future"})
	}

	episode := resource.Episode{CapturedAt: now, Session: resource.Session{
		Key: "100:1", RootPID: 100, RootStartedAt: now.Add(-time.Minute), RSSBytes: 4 << 30,
		Processes: []resource.Process{
			{PID: 100, Name: "codex", StartedAt: now.Add(-time.Minute)},
			{PID: 101, Name: "node", StartedAt: now.Add(-8 * time.Second)},
		},
		Samples: []resource.Sample{
			{At: now.Add(-10 * time.Second), RSSBytes: 1 << 30},
			{At: now, RSSBytes: 4 << 30},
		},
	}}
	if err := st.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}

	got := st.RecentResourceEpisodes(1)[0]
	if len(got.Activities) != 4 {
		t.Fatalf("activities=%+v want process start plus three matching stored events", got.Activities)
	}
	for _, activity := range got.Activities {
		if activity.PID == 999 || activity.At.After(now) {
			t.Fatalf("unrelated or future activity leaked into episode: %+v", activity)
		}
		if strings.Contains(activity.Summary, "/Users/alice") {
			t.Fatalf("activity retained a full local path: %+v", activity)
		}
		if strings.Contains(activity.Summary, "recycled-pid") {
			t.Fatalf("activity predating this child process lifetime was included: %+v", activity)
		}
	}
	if len(got.Correlations) != 1 || got.Correlations[0].ActivityCount != 4 {
		t.Fatalf("correlations=%+v", got.Correlations)
	}
}

func TestRefreshResourceEpisodeMergesConcurrentEnrichment(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Add(-time.Minute)
	episode := resource.Episode{CapturedAt: now, Session: resource.Session{
		Key: "100:1", RootPID: 100, RootStartedAt: now.Add(-time.Minute),
		Processes: []resource.Process{{PID: 100, Name: "codex", StartedAt: now.Add(-time.Minute)}},
		Samples:   []resource.Sample{{At: now.Add(-10 * time.Second), RSSBytes: 1 << 30}, {At: now, RSSBytes: 2 << 30}},
	}}
	if err := st.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	var id int64
	var stalePayload string
	if err := st.db.QueryRow(`SELECT id, episode_json FROM resource_episodes LIMIT 1`).Scan(&id, &stalePayload); err != nil {
		t.Fatal(err)
	}
	var stale resource.Episode
	if err := json.Unmarshal([]byte(stalePayload), &stale); err != nil {
		t.Fatal(err)
	}

	concurrent := stale
	concurrent.ActivityStatus = "complete"
	concurrent.Activities = []resource.EpisodeActivity{{At: now.Add(-2 * time.Second), Kind: "guard", PID: 100, Summary: "guard resolved"}}
	concurrentPayload, _ := json.Marshal(concurrent)
	if _, err := st.db.Exec(`UPDATE resource_episodes SET episode_json = ? WHERE id = ?`, string(concurrentPayload), id); err != nil {
		t.Fatal(err)
	}
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(-time.Second), PID: 100, Detail: "late tool action"})

	stale.ID = id
	got := st.refreshResourceEpisode(context.Background(), id, stalePayload, stale)
	if len(got.Activities) != 2 {
		t.Fatalf("activities=%+v want concurrent and late evidence", got.Activities)
	}
	stored := st.RecentResourceEpisodes(1)
	if len(stored) != 1 || len(stored[0].Activities) != 2 || stored[0].ActivityStatus != "complete" {
		t.Fatalf("stored episode lost concurrent evidence: %+v", stored)
	}
}

func TestRecentResourceEpisodesAddsLatePersistedActivityBeforeFinalizing(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	episode := resource.Episode{CapturedAt: now, Session: resource.Session{
		Key: "100:1", RootPID: 100, RootStartedAt: now.Add(-time.Minute),
		Processes: []resource.Process{{PID: 100, Name: "codex", StartedAt: now.Add(-time.Minute)}},
		Samples:   []resource.Sample{{At: now.Add(-10 * time.Second), RSSBytes: 1 << 30}, {At: now, RSSBytes: 2 << 30}},
	}}
	if err := st.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	first := st.RecentResourceEpisodes(1)
	if len(first) != 1 || len(first[0].Activities) != 0 || first[0].ActivityStatus != "settling" {
		t.Fatalf("initial episode=%+v", first)
	}

	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(-time.Second), PID: 100, Detail: "late persisted tool action"})
	second := st.RecentResourceEpisodes(1)
	if len(second) != 1 || len(second[0].Activities) != 1 || second[0].Activities[0].Summary != "late persisted tool action" {
		t.Fatalf("episode was not re-enriched from late event: %+v", second)
	}
}

// Harness trace rows carry no pid: an episode reads them by its session id,
// and a tool call completed after capture replaces its started copy.
func TestResourceEpisodeJoinsSessionTraceRows(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	rootStart := now.Add(-time.Hour)
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", RootPID: 100, RootStartedAt: rootStart.Format(time.RFC3339Nano), StartedAt: rootStart, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now.Add(-4 * time.Second), SessionID: "s1", ToolName: "Bash", ToolStatus: "running", CallID: "toolu_1"})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-3 * time.Second), SessionID: "s1", Model: "claude-opus-5-5", TokensIn: 593, TokensOut: 557})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now.Add(-3 * time.Second), SessionID: "other", ToolName: "Read", ToolStatus: "ok", CallID: "toolu_2"})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-40 * time.Second), SessionID: "s1", Model: "before-the-window"})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now.Add(-20 * time.Second), SessionID: "s1", ToolName: "Read", ToolStatus: "running", CallID: "toolu_3"})

	episode := resource.Episode{CapturedAt: now, Session: resource.Session{
		Key: fmt.Sprintf("100:%d", rootStart.UnixNano()), Name: "claude", RootPID: 100, RootStartedAt: rootStart,
		Processes: []resource.Process{{PID: 100, Name: "claude", StartedAt: rootStart}},
		Samples:   []resource.Sample{{At: now.Add(-30 * time.Second), RSSBytes: 1 << 30}, {At: now.Add(-6 * time.Second), RSSBytes: 1 << 30}, {At: now, RSSBytes: 4 << 30}},
	}}
	if err := st.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := st.db.QueryRow(`SELECT episode_json FROM resource_episodes`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var stored resource.Episode
	if err := json.Unmarshal([]byte(payload), &stored); err != nil || len(stored.Activities) != 3 {
		t.Fatalf("capture-time payload activities=%+v (%v), want the session rows before any read", stored.Activities, err)
	}
	got := st.RecentResourceEpisodes(1)[0]
	if got.SessionID != "s1" || len(got.Activities) != 3 {
		t.Fatalf("session=%q activities=%+v want the three s1 rows inside the window", got.SessionID, got.Activities)
	}
	for _, activity := range got.Activities {
		if activity.Process != "claude" || activity.PID != 0 {
			t.Fatalf("session row not named for the session: %+v", activity)
		}
	}
	// Read started before the rise and was still running at capture.
	if c := got.Correlations; len(c) != 1 || c[0].ActivityCount != 3 ||
		c[0].Summary != "Memory rose 3.0 GiB in 6s while Read was running (and 2 other recorded activities)." {
		t.Fatalf("correlations=%+v", c)
	}

	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now.Add(-4 * time.Second), SessionID: "s1", ToolName: "Bash", ToolStatus: "ok", DurationMs: 2500, CallID: "toolu_1"})
	got = st.RecentResourceEpisodes(1)[0]
	var tools []resource.EpisodeActivity
	for _, activity := range got.Activities {
		if activity.Kind == "tool" {
			tools = append(tools, activity)
		}
	}
	if len(tools) != 2 || tools[1].Summary != "Bash returned after 2.5s" || !tools[1].EndedAt.Equal(now.Add(-1500*time.Millisecond)) {
		t.Fatalf("completed tool call=%+v want one Bash row, returned, with its end", tools)
	}
}

// ES rows are stored with their event time and can arrive late: an episode
// keeps settling until the file feed has reached its capture.
func TestResourceEpisodeSettlesOnFileFeedClock(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	captured := time.Now().UTC().Add(-time.Minute)
	st.TrackFileFeed()
	st.NoteFileFeed(captured.Add(-2 * time.Hour))
	episode := resource.Episode{CapturedAt: captured, Session: resource.Session{
		Key: "100:1", RootPID: 100, RootStartedAt: captured.Add(-time.Hour),
		Processes: []resource.Process{{PID: 100, Name: "claude", StartedAt: captured.Add(-time.Hour)}},
		Samples:   []resource.Sample{{At: captured.Add(-6 * time.Second), RSSBytes: 1 << 30}, {At: captured, RSSBytes: 4 << 30}},
	}}
	if err := st.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	if got := st.RecentResourceEpisodes(1)[0]; got.ActivityStatus != "settling" {
		t.Fatalf("status=%q while the file feed is two hours behind", got.ActivityStatus)
	}

	st.PutEvent(event.Event{Kind: event.KindExec, TS: captured.Add(-2 * time.Second), PID: 100, ExePath: "/bin/zsh"})
	st.NoteFileFeed(captured.Add(time.Second))
	st.NoteFileFeed(captured.Add(-time.Hour)) // an older event does not move the clock back
	got := st.RecentResourceEpisodes(1)[0]
	if got.ActivityStatus != "complete" || len(got.Activities) != 1 || got.Correlations[0].ActivityCount != 1 {
		t.Fatalf("episode=%+v want the late exec row and a final status", got)
	}

	cases := []struct {
		name     string
		captured time.Time
		feed     time.Time
		want     bool
	}{
		{"inside the settle window", time.Now().Add(-10 * time.Second), time.Now(), false},
		{"feed behind", time.Now().Add(-time.Minute), time.Now().Add(-time.Hour), false},
		{"feed caught up", time.Now().Add(-time.Minute), time.Now(), true},
		{"feed never delivered", time.Now().Add(-time.Minute), time.Time{}, true},
		{"feed behind past the cap", time.Now().Add(-episodeSettleMax), time.Now().Add(-time.Hour), true},
	}
	for _, tc := range cases {
		fresh, err := Open("", "")
		if err != nil {
			t.Fatal(err)
		}
		fresh.TrackFileFeed()
		if !tc.feed.IsZero() {
			fresh.NoteFileFeed(tc.feed)
		}
		if got := fresh.episodeSettled(tc.captured); got != tc.want {
			t.Fatalf("%s: settled=%v want %v", tc.name, got, tc.want)
		}
		fresh.Close()
	}
	untracked, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer untracked.Close()
	if !untracked.episodeSettled(time.Now().Add(-time.Minute)) {
		t.Fatal("without an ES feed an episode settles after the settle window")
	}
}
