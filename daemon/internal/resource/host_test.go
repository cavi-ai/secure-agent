package resource

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
)

func TestDeriveHostSnapshotAttributesAgentAndNonAgentPressure(t *testing.T) {
	cpu := 75.0
	load := 5.5
	host := deriveHostSnapshot(rawHostSample{
		TotalMemoryBytes:     16 * gib,
		AvailableMemoryBytes: 4 * gib,
		AvailableMemoryKnown: true,
		SwapTotalBytes:       8 * gib,
		SwapUsedBytes:        2 * gib,
		SystemCPUPercent:     &cpu,
		Load1:                &load,
		LogicalCPUCount:      8,
		ThermalState:         "nominal",
		AgentCPUPercent:      func() *float64 { value := 20.0; return &value }(),
	}, 3*gib)

	if host.UsedMemoryBytes != 12*gib || host.NonAgentMemoryBytes != 9*gib {
		t.Fatalf("memory attribution=%+v", host)
	}
	if host.AgentMemoryPercent != 18.8 || host.HeadroomPercent != 25 {
		t.Fatalf("memory percentages=%+v", host)
	}
	if host.AgentCPUPercent == nil || *host.AgentCPUPercent != 20 || host.NonAgentCPUPercent == nil || *host.NonAgentCPUPercent != 55 {
		t.Fatalf("CPU attribution=%+v", host)
	}
	if host.MemoryPressure != "normal" || host.Capacity != "constrained" || host.HeadroomScore != 25 {
		t.Fatalf("pressure posture=%+v", host)
	}
}

func TestDeriveHostSnapshotClampsAttributionAndReportsCriticalPressure(t *testing.T) {
	cpu := 10.0
	host := deriveHostSnapshot(rawHostSample{
		TotalMemoryBytes:     16 * gib,
		AvailableMemoryBytes: gib,
		AvailableMemoryKnown: true,
		SwapTotalBytes:       4 * gib,
		SwapUsedBytes:        4 * gib,
		SystemCPUPercent:     &cpu,
		LogicalCPUCount:      4,
		ThermalState:         "serious",
		AgentCPUPercent:      func() *float64 { value := 50.0; return &value }(),
	}, 20*gib)

	if host.NonAgentMemoryBytes != 0 || host.NonAgentCPUPercent == nil || *host.NonAgentCPUPercent != 0 {
		t.Fatalf("attribution must not underflow: %+v", host)
	}
	if host.MemoryPressure != "critical" || host.Capacity != "critical" || host.HeadroomScore >= 30 {
		t.Fatalf("critical posture=%+v", host)
	}
}

func TestDeriveHostSnapshotDoesNotInventUnavailablePressure(t *testing.T) {
	host := deriveHostSnapshot(rawHostSample{}, 0)
	if host.MemoryPressure != "unknown" || host.ThermalState != "unknown" || host.Capacity != "unknown" {
		t.Fatalf("unavailable metrics=%+v", host)
	}
}

func TestDeriveHostSnapshotDoesNotTreatMissingAvailableMemoryAsZero(t *testing.T) {
	cpu := 25.0
	host := deriveHostSnapshot(rawHostSample{
		TotalMemoryBytes: 16 * gib, SystemCPUPercent: &cpu,
		LogicalCPUCount: 8, ThermalState: "unknown",
	}, gib)
	if host.MemoryPressure != "unknown" {
		t.Fatalf("memory pressure=%q want unknown", host.MemoryPressure)
	}
	if host.HeadroomScore != 75 || host.Capacity != "ample" {
		t.Fatalf("CPU-only headroom=%+v", host)
	}
	if host.UsedMemoryBytes != 0 || host.NonAgentMemoryBytes != 0 {
		t.Fatalf("missing available memory must not invent usage: %+v", host)
	}
	memoryOnly := deriveHostSnapshot(rawHostSample{TotalMemoryBytes: 16 * gib}, gib)
	if memoryOnly.Capacity != "unknown" {
		t.Fatalf("total memory without available memory must not create capacity alarm: %+v", memoryOnly)
	}
}

func TestDeriveHostSnapshotUsesAlignedAgentCPU(t *testing.T) {
	system, agent := 75.0, 20.0
	host := deriveHostSnapshot(rawHostSample{
		SystemCPUPercent: &system, AgentCPUPercent: &agent,
		LogicalCPUCount: 8,
	}, 0)
	if host.AgentCPUPercent == nil || *host.AgentCPUPercent != 20 {
		t.Fatalf("agent CPU=%v want aligned 20", host.AgentCPUPercent)
	}
	if host.NonAgentCPUPercent == nil || *host.NonAgentCPUPercent != 55 {
		t.Fatalf("non-agent CPU=%v want 55", host.NonAgentCPUPercent)
	}
}

func TestAgentCPUPercentUsesSameSamplingInterval(t *testing.T) {
	previous := map[int32]time.Duration{10: time.Second, 20: 2 * time.Second}
	current := map[int32]time.Duration{10: 2 * time.Second, 20: 4 * time.Second}
	got, ok := agentCPUPercentFromDurations(previous, current, 5*time.Second, 4)
	if !ok || got != 15 {
		t.Fatalf("agent CPU=%v ok=%v want 15", got, ok)
	}
}

func TestAgentCPUPercentIsUnavailableWhenAgentPIDSetChanges(t *testing.T) {
	previous := map[int32]time.Duration{10: time.Second, 20: 2 * time.Second}
	current := map[int32]time.Duration{10: 2 * time.Second, 30: time.Second}
	if _, ok := agentCPUPercentFromDurations(previous, current, 5*time.Second, 4); ok {
		t.Fatal("PID churn must make agent CPU attribution unavailable")
	}
}

func TestTrackerSamplesHostAtResourceCadence(t *testing.T) {
	started := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	calls := 0
	tracker := newTrackerWithHostSampler(func(map[int32]time.Duration) rawHostSample {
		calls++
		agent := 10.0
		return rawHostSample{TotalMemoryBytes: 16 * gib, AvailableMemoryBytes: 8 * gib, AvailableMemoryKnown: true, AgentCPUPercent: &agent, LogicalCPUCount: 8}
	})
	infos := map[int32]agents.AgentInfo{
		100: {Name: "codex", PID: 100, RootPID: 100, StartedAt: started, RSSBytes: gib, CPUPercent: 80},
	}

	tracker.Observe(infos, nil, started)
	tracker.Observe(infos, nil, started.Add(4*time.Second))
	if calls != 1 {
		t.Fatalf("host samples inside cadence=%d want 1", calls)
	}
	tracker.Observe(infos, nil, started.Add(5*time.Second))
	if calls != 2 {
		t.Fatalf("host samples at cadence=%d want 2", calls)
	}
	host := tracker.Snapshot().Host
	if host == nil || host.AgentMemoryBytes != gib || host.AgentCPUPercent == nil || *host.AgentCPUPercent != 10 {
		t.Fatalf("host snapshot=%+v", host)
	}
}
