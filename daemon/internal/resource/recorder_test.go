package resource

import (
	"testing"
	"time"
)

func TestRecorderCapturesPressureTransitionsAndEscalation(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	recorder := NewRecorder()
	session := Session{Key: "100:1", RootPID: 100, RSSBytes: 4 * gib, Samples: []Sample{{At: now, RSSBytes: 4 * gib}}}

	if got := recorder.Observe(Snapshot{ObservedAt: now, Sessions: []Session{session}}); len(got) != 0 {
		t.Fatalf("healthy episodes=%d want 0", len(got))
	}

	session.Diagnoses = []Diagnosis{{Code: "heavy-memory", Severity: "critical", Summary: "large"}}
	first := recorder.Observe(Snapshot{ObservedAt: now.Add(time.Second), Sessions: []Session{session}})
	if len(first) != 1 || first[0].Session.Key != session.Key || first[0].Severity != "critical" {
		t.Fatalf("first episode=%+v", first)
	}
	if got := recorder.Observe(Snapshot{ObservedAt: now.Add(2 * time.Second), Sessions: []Session{session}}); len(got) != 0 {
		t.Fatalf("duplicate episodes=%d want 0", len(got))
	}

	session.RSSBytes = 5 * gib
	session.Samples = append(session.Samples, Sample{At: now.Add(3 * time.Second), RSSBytes: 5 * gib})
	if got := recorder.Observe(Snapshot{ObservedAt: now.Add(3 * time.Second), Sessions: []Session{session}}); len(got) != 1 {
		t.Fatalf("escalation episodes=%d want 1", len(got))
	}

	session.Diagnoses = nil
	recorder.Observe(Snapshot{ObservedAt: now.Add(4 * time.Second), Sessions: []Session{session}})
	session.Diagnoses = []Diagnosis{{Code: "heavy-memory", Severity: "critical"}}
	if got := recorder.Observe(Snapshot{ObservedAt: now.Add(5 * time.Second), Sessions: []Session{session}}); len(got) != 1 {
		t.Fatalf("reopened episodes=%d want 1", len(got))
	}
}

func TestRecorderBoundsStoredTrend(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	samples := make([]Sample, episodeSampleLimit+10)
	for i := range samples {
		samples[i] = Sample{At: now.Add(time.Duration(i) * time.Second), RSSBytes: uint64(i)}
	}
	processes := make([]Process, episodeProcessLimit+10)
	for i := range processes {
		processes[i] = Process{PID: int32(100 + i), RSSBytes: uint64(i)}
	}
	session := Session{Key: "100:1", RootPID: 100, RSSBytes: 4 * gib, Samples: samples, Processes: processes, ProcessCount: len(processes),
		Diagnoses: []Diagnosis{{Code: "heavy-memory", Severity: "critical"}}}

	episodes := NewRecorder().Observe(Snapshot{ObservedAt: now, Sessions: []Session{session}})
	if len(episodes) != 1 || len(episodes[0].Session.Samples) != episodeSampleLimit {
		t.Fatalf("episode samples=%d want %d", len(episodes[0].Session.Samples), episodeSampleLimit)
	}
	if episodes[0].Session.Samples[0].RSSBytes != 10 {
		t.Fatalf("oldest retained sample=%d want 10", episodes[0].Session.Samples[0].RSSBytes)
	}
	if len(episodes[0].Session.Processes) != episodeProcessLimit {
		t.Fatalf("episode processes=%d want %d", len(episodes[0].Session.Processes), episodeProcessLimit)
	}
	if !episodeHasPID(episodes[0], 100) {
		t.Fatal("bounded process breakdown dropped the session root")
	}
}

func TestRecorderRetryReemitsActivePressure(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	recorder := NewRecorder()
	snapshot := Snapshot{ObservedAt: now, Sessions: []Session{{Key: "100:1", RSSBytes: 4 * gib,
		Diagnoses: []Diagnosis{{Code: "heavy-memory", Severity: "critical"}}}}}
	if got := recorder.Observe(snapshot); len(got) != 1 {
		t.Fatalf("first episodes=%d want 1", len(got))
	}
	recorder.Retry("100:1")
	if got := recorder.Observe(snapshot); len(got) != 1 {
		t.Fatalf("retry episodes=%d want 1", len(got))
	}
}

func TestAttachEpisodeActivityExplainsSteepestGrowthWithoutClaimingCausation(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	episode := Episode{CapturedAt: now.Add(15 * time.Second), Session: Session{
		RSSBytes: 4 * gib,
		Samples: []Sample{
			{At: now, RSSBytes: gib},
			{At: now.Add(5 * time.Second), RSSBytes: gib + 128*1024*1024},
			{At: now.Add(10 * time.Second), RSSBytes: 4 * gib},
		},
	}}

	got := AttachEpisodeActivity(episode, []EpisodeActivity{
		{At: now.Add(2 * time.Second), Kind: "tool", PID: 100, Summary: "Read tool ran"},
		{At: now.Add(8 * time.Second), Kind: "process-start", PID: 101, Process: "node", Summary: "node started"},
	})

	if len(got.Activities) != 2 {
		t.Fatalf("activities=%d want 2", len(got.Activities))
	}
	if len(got.Correlations) != 1 {
		t.Fatalf("correlations=%d want 1", len(got.Correlations))
	}
	correlation := got.Correlations[0]
	if correlation.Confidence != "observed-correlation" {
		t.Fatalf("confidence=%q", correlation.Confidence)
	}
	if correlation.RSSDeltaBytes != 3*gib-128*1024*1024 || correlation.ActivityCount != 1 {
		t.Fatalf("correlation=%+v", correlation)
	}
	if correlation.Summary != "Memory rose 2.9 GiB in 5s while node started." {
		t.Fatalf("summary=%q", correlation.Summary)
	}
}

func TestAttachEpisodeActivityBoundsNewestEvidence(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	activities := make([]EpisodeActivity, episodeActivityLimit+5)
	for i := range activities {
		activities[i] = EpisodeActivity{At: now.Add(time.Duration(i) * time.Second), PID: int32(i + 1)}
	}
	got := AttachEpisodeActivity(Episode{}, activities)
	if len(got.Activities) != episodeActivityLimit {
		t.Fatalf("activities=%d want %d", len(got.Activities), episodeActivityLimit)
	}
	if got.Activities[0].PID != 6 {
		t.Fatalf("oldest retained pid=%d want 6", got.Activities[0].PID)
	}
}

func episodeHasPID(episode Episode, pid int32) bool {
	for _, process := range episode.Session.Processes {
		if process.PID == pid {
			return true
		}
	}
	return false
}
