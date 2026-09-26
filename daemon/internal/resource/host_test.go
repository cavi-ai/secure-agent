package resource

import (
	"math"
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

// A 128 GiB Mac with ~70.7 GiB still free and swap at 13.55/15 GiB (the
// console prints that as 13.6 / 15.0 GB). The score is swap still free,
// which rounds to 10, and under 15 the capacity band is critical. Free RAM
// stays ~55% and is not the score.
func TestHeadroomScoreFollowsFullSwapWhileRAMRemains(t *testing.T) {
	cpu := 12.1
	host := deriveHostSnapshot(rawHostSample{
		TotalMemoryBytes:     128 * gib,
		AvailableMemoryBytes: uint64(math.Round(70.7 * float64(gib))),
		AvailableMemoryKnown: true,
		SwapTotalBytes:       15 * gib,
		SwapUsedBytes:        uint64(math.Round(13.55 * float64(gib))),
		SystemCPUPercent:     &cpu,
		AgentCPUPercent:      func() *float64 { v := 1.2; return &v }(),
		LogicalCPUCount:      8,
		ThermalState:         "unknown",
	}, uint64(math.Round(0.298*128*float64(gib))))

	if host.HeadroomPercent != 55.2 {
		t.Fatalf("RAM still available = %v%%, want 55.2", host.HeadroomPercent)
	}
	if host.HeadroomScore != 10 || host.Capacity != "critical" || host.HeadroomLimiter != "swap" {
		t.Fatalf("headroom=%d capacity=%s limiter=%s, want 10 critical swap", host.HeadroomScore, host.Capacity, host.HeadroomLimiter)
	}
	if host.MemoryPressure != "critical" {
		t.Fatalf("pressure=%s, want critical because swap is past 80%%", host.MemoryPressure)
	}
}

func TestHeadroomCapacityBandIsNotMemoryPressure(t *testing.T) {
	cpu := 0.0
	// Swap 85% full → pressure critical, but 15 points of swap remain, so
	// the score band is constrained, not critical. 80% RAM is still free.
	constrained := deriveHostSnapshot(rawHostSample{
		TotalMemoryBytes: 100 * gib, AvailableMemoryBytes: 80 * gib, AvailableMemoryKnown: true,
		SwapTotalBytes: 100 * gib, SwapUsedBytes: 85 * gib,
		SystemCPUPercent: &cpu, ThermalState: "nominal", LogicalCPUCount: 8,
	}, 0)
	if constrained.MemoryPressure != "critical" || constrained.HeadroomScore != 15 || constrained.Capacity != "constrained" || constrained.HeadroomLimiter != "swap" {
		t.Fatalf("15 points of swap free: %+v", constrained)
	}
	critical := deriveHostSnapshot(rawHostSample{
		TotalMemoryBytes: 100 * gib, AvailableMemoryBytes: 80 * gib, AvailableMemoryKnown: true,
		SwapTotalBytes: 100 * gib, SwapUsedBytes: 86 * gib,
		SystemCPUPercent: &cpu, ThermalState: "nominal", LogicalCPUCount: 8,
	}, 0)
	if critical.HeadroomScore != 14 || critical.Capacity != "critical" || critical.HeadroomLimiter != "swap" {
		t.Fatalf("14 points of swap free: %+v", critical)
	}
	ample := deriveHostSnapshot(rawHostSample{
		TotalMemoryBytes: 100 * gib, AvailableMemoryBytes: 80 * gib, AvailableMemoryKnown: true,
		SwapTotalBytes: 100 * gib, SwapUsedBytes: 50 * gib,
		SystemCPUPercent: &cpu, ThermalState: "nominal", LogicalCPUCount: 8,
	}, 0)
	if ample.HeadroomScore != 50 || ample.Capacity != "ample" || ample.MemoryPressure != "warning" {
		t.Fatalf("half the swap used is warning pressure and an ample score: %+v", ample)
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
