package store

import (
	"testing"
	"time"

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
