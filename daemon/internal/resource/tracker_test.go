package resource

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
)

const gib = uint64(1024 * 1024 * 1024)

func TestTrackerAggregatesSessionTree(t *testing.T) {
	started := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	now := started.Add(2 * time.Hour)
	tracker := NewTracker()
	tracker.Observe(map[int32]agents.AgentInfo{
		100: {Name: "claude", PID: 100, PPID: 1, RootPID: 100, CWD: "/workspace/api", StartedAt: started, RSSBytes: gib, CPUPercent: 30},
		101: {Name: "claude", PID: 101, PPID: 100, RootPID: 100, CWD: "/workspace/api", StartedAt: started.Add(time.Second), RSSBytes: gib / 2, CPUPercent: 20},
		102: {Name: "claude", PID: 102, PPID: 999, RootPID: 100, CWD: "/workspace/api", StartedAt: started.Add(2 * time.Second), RSSBytes: gib / 4, CPUPercent: 10, IsOrphan: true},
	}, map[int32]string{
		100: now.Add(-time.Minute).Format(time.RFC3339Nano),
		101: now.Add(-time.Second).Format(time.RFC3339Nano),
	}, now)

	snapshot := tracker.Snapshot()
	if len(snapshot.Sessions) != 1 {
		t.Fatalf("sessions=%d want 1", len(snapshot.Sessions))
	}
	session := snapshot.Sessions[0]
	if session.RootPID != 100 || !session.RootStartedAt.Equal(started) {
		t.Fatalf("root identity=(%d,%v) want (100,%v)", session.RootPID, session.RootStartedAt, started)
	}
	if session.RSSBytes != gib+gib/2+gib/4 || session.CPUPercent != 60 {
		t.Fatalf("resources=(%d,%v) want (%d,60)", session.RSSBytes, session.CPUPercent, gib+gib/2+gib/4)
	}
	if session.ProcessCount != 3 || session.OrphanCount != 1 || len(session.Processes) != 3 {
		t.Fatalf("counts=%d processes/%d orphans breakdown=%d", session.ProcessCount, session.OrphanCount, len(session.Processes))
	}
	if session.LastSeenAt != now.Add(-time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("last_seen=%q", session.LastSeenAt)
	}
	if snapshot.RSSBytes != session.RSSBytes || snapshot.CPUPercent != session.CPUPercent || snapshot.ProcessCount != 3 {
		t.Fatalf("snapshot totals=%+v", snapshot)
	}
}

func TestTrackerSamplesAtFiveSecondsAndCapsHistory(t *testing.T) {
	started := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	tracker := NewTracker()
	infos := map[int32]agents.AgentInfo{
		100: {Name: "claude", PID: 100, PPID: 1, RootPID: 100, StartedAt: started, RSSBytes: 100, CPUPercent: 10},
	}

	tracker.Observe(infos, nil, started)
	tracker.Observe(infos, nil, started.Add(4*time.Second))
	if got := len(tracker.Snapshot().Sessions[0].Samples); got != 1 {
		t.Fatalf("samples inside interval=%d want 1", got)
	}
	tracker.Observe(infos, nil, started.Add(5*time.Second))
	if got := len(tracker.Snapshot().Sessions[0].Samples); got != 2 {
		t.Fatalf("samples at interval=%d want 2", got)
	}

	for i := 2; i <= maxSessionSamples; i++ {
		tracker.Observe(infos, nil, started.Add(time.Duration(i)*sampleInterval))
	}
	samples := tracker.Snapshot().Sessions[0].Samples
	if len(samples) != maxSessionSamples {
		t.Fatalf("samples=%d want cap %d", len(samples), maxSessionSamples)
	}
	if !samples[0].At.Equal(started.Add(sampleInterval)) {
		t.Fatalf("oldest sample=%v want %v", samples[0].At, started.Add(sampleInterval))
	}
}

func TestSnapshotReturnsImmutableCopies(t *testing.T) {
	started := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	tracker := NewTracker()
	tracker.Observe(map[int32]agents.AgentInfo{
		100: {Name: "claude", PID: 100, RootPID: 100, StartedAt: started, RSSBytes: 100},
	}, nil, started)

	first := tracker.Snapshot()
	first.Sessions[0].Processes[0].RSSBytes = 999
	first.Sessions[0].Samples[0].RSSBytes = 999
	second := tracker.Snapshot()
	if second.Sessions[0].Processes[0].RSSBytes != 100 || second.Sessions[0].Samples[0].RSSBytes != 100 {
		t.Fatalf("snapshot mutation escaped copy: %+v", second.Sessions[0])
	}
}

func TestDiagnosesTriggerAtThresholds(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	session := Session{
		RootPID:      100,
		RSSBytes:     5 * gib,
		CPUPercent:   100,
		LastSeenAt:   now.Add(-15 * time.Minute).Format(time.RFC3339Nano),
		ProcessCount: 2,
		OrphanCount:  1,
		Processes: []Process{
			{PID: 100, RSSBytes: 3 * gib},
			{PID: 101, PPID: 100, RSSBytes: 2 * gib, IsOrphan: true},
		},
	}
	history := []Sample{{At: now.Add(-15 * time.Minute), RSSBytes: 4 * gib}}

	got := diagnosisCodes(diagnoseSession(session, history, now))
	want := []string{"heavy-cpu", "heavy-memory", "idle-heavy", "orphan-drift", "rapid-growth"}
	if len(got) != len(want) {
		t.Fatalf("diagnoses=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("diagnoses=%v want %v", got, want)
		}
	}

	runaway := session
	runaway.RSSBytes = 5 * gib
	runaway.Processes = []Process{{PID: 100, RSSBytes: 2 * gib}, {PID: 101, PPID: 100, RSSBytes: 3 * gib}}
	if !hasDiagnosis(diagnoseSession(runaway, nil, now), "runaway-child") {
		t.Fatal("runaway-child did not trigger at 60% and >= 1 GiB")
	}
}

func TestDiagnosesDoNotTriggerBelowBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	session := Session{
		RootPID:    100,
		RSSBytes:   4*gib - 1,
		CPUPercent: 99.99,
		LastSeenAt: now.Add(-15*time.Minute + time.Nanosecond).Format(time.RFC3339Nano),
		Processes: []Process{
			{PID: 100, RSSBytes: 3*gib - 1},
			{PID: 101, PPID: 100, RSSBytes: gib - 1},
		},
	}
	history := []Sample{{At: now.Add(-15 * time.Minute), RSSBytes: 7 * gib / 2}}
	if got := diagnoseSession(session, history, now); len(got) != 0 {
		t.Fatalf("below-boundary diagnoses=%v want none", diagnosisCodes(got))
	}
}

func diagnosisCodes(diagnoses []Diagnosis) []string {
	codes := make([]string, len(diagnoses))
	for i := range diagnoses {
		codes[i] = diagnoses[i].Code
	}
	return codes
}

func hasDiagnosis(diagnoses []Diagnosis, code string) bool {
	for _, diagnosis := range diagnoses {
		if diagnosis.Code == code {
			return true
		}
	}
	return false
}
