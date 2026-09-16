package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

func TestResourceEpisodeRoundTrip(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	want := resource.Episode{
		CapturedAt: now, Severity: "critical", DiagnosisCodes: []string{"heavy-memory"},
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
	if got[0].ID == 0 || !got[0].CapturedAt.Equal(now) || got[0].Session.Workspace != "/work/app" || got[0].Session.Processes[0].PID != 100 {
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
