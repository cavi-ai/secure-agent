package resource

import (
	"math"
	"runtime"
	"time"
)

// HostSnapshot puts attributed agent use in the context of the whole machine.
// CPU percentages are shares of total machine capacity (0-100), unlike the
// existing per-process figures where 100 represents one fully occupied core.
type HostSnapshot struct {
	TotalMemoryBytes      uint64   `json:"total_memory_bytes,omitempty"`
	FreeMemoryBytes       uint64   `json:"free_memory_bytes,omitempty"`
	AvailableMemoryBytes  uint64   `json:"available_memory_bytes,omitempty"`
	CompressedMemoryBytes uint64   `json:"compressed_memory_bytes,omitempty"`
	UsedMemoryBytes       uint64   `json:"used_memory_bytes,omitempty"`
	AgentMemoryBytes      uint64   `json:"agent_memory_bytes,omitempty"`
	NonAgentMemoryBytes   uint64   `json:"non_agent_memory_bytes,omitempty"`
	SwapTotalBytes        uint64   `json:"swap_total_bytes,omitempty"`
	SwapUsedBytes         uint64   `json:"swap_used_bytes,omitempty"`
	HeadroomPercent       float64  `json:"headroom_percent,omitempty"`
	AgentMemoryPercent    float64  `json:"agent_memory_percent,omitempty"`
	SystemCPUPercent      *float64 `json:"system_cpu_percent,omitempty"`
	AgentCPUPercent       *float64 `json:"agent_cpu_percent,omitempty"`
	NonAgentCPUPercent    *float64 `json:"non_agent_cpu_percent,omitempty"`
	Load1                 *float64 `json:"load_1,omitempty"`
	LogicalCPUCount       int      `json:"logical_cpu_count,omitempty"`
	MemoryPressure        string   `json:"memory_pressure"`
	ThermalState          string   `json:"thermal_state"`
	HeadroomScore         int      `json:"headroom_score"`
	Capacity              string   `json:"capacity"`
}

type rawHostSample struct {
	TotalMemoryBytes      uint64
	FreeMemoryBytes       uint64
	AvailableMemoryBytes  uint64
	AvailableMemoryKnown  bool
	CompressedMemoryBytes uint64
	SwapTotalBytes        uint64
	SwapUsedBytes         uint64
	SystemCPUPercent      *float64
	AgentCPUPercent       *float64
	Load1                 *float64
	LogicalCPUCount       int
	ThermalState          string
}

type hostSampler func(map[int32]time.Duration) rawHostSample

func deriveHostSnapshot(raw rawHostSample, agentMemory uint64) HostSnapshot {
	if raw.LogicalCPUCount <= 0 {
		raw.LogicalCPUCount = runtime.NumCPU()
	}
	host := HostSnapshot{
		TotalMemoryBytes: raw.TotalMemoryBytes, FreeMemoryBytes: raw.FreeMemoryBytes,
		AvailableMemoryBytes: raw.AvailableMemoryBytes, CompressedMemoryBytes: raw.CompressedMemoryBytes,
		SwapTotalBytes: raw.SwapTotalBytes, SwapUsedBytes: raw.SwapUsedBytes,
		SystemCPUPercent: cloneFloat(raw.SystemCPUPercent), AgentCPUPercent: cloneFloat(raw.AgentCPUPercent), Load1: cloneFloat(raw.Load1),
		LogicalCPUCount: raw.LogicalCPUCount, ThermalState: raw.ThermalState,
		AgentMemoryBytes: agentMemory,
	}
	if host.ThermalState == "" {
		host.ThermalState = "unknown"
	}
	if raw.TotalMemoryBytes > 0 && raw.AvailableMemoryKnown {
		available := min(raw.AvailableMemoryBytes, raw.TotalMemoryBytes)
		host.AvailableMemoryBytes = available
		host.UsedMemoryBytes = raw.TotalMemoryBytes - available
		host.NonAgentMemoryBytes = saturatingSubtract(host.UsedMemoryBytes, agentMemory)
		host.HeadroomPercent = round1(percent(available, raw.TotalMemoryBytes))
		host.AgentMemoryPercent = round1(percent(min(agentMemory, raw.TotalMemoryBytes), raw.TotalMemoryBytes))
	}
	if raw.SystemCPUPercent != nil && raw.AgentCPUPercent != nil {
		nonAgent := round1(clamp(*raw.SystemCPUPercent-*raw.AgentCPUPercent, 0, 100))
		host.NonAgentCPUPercent = &nonAgent
	}
	host.MemoryPressure = memoryPressure(host.HeadroomPercent, raw.TotalMemoryBytes, raw.AvailableMemoryKnown, raw.SwapUsedBytes, raw.SwapTotalBytes)
	host.HeadroomScore = headroomScore(host)
	if !raw.AvailableMemoryKnown && raw.SystemCPUPercent == nil && raw.SwapTotalBytes == 0 && host.ThermalState == "unknown" {
		host.Capacity = "unknown"
	} else {
		host.Capacity = capacityLabel(host.HeadroomScore)
	}
	return host
}

func memoryPressure(headroom float64, total uint64, availableKnown bool, swapUsed, swapTotal uint64) string {
	if total == 0 || !availableKnown {
		return "unknown"
	}
	swapPercent := percent(swapUsed, swapTotal)
	if headroom < 10 || swapPercent >= 80 {
		return "critical"
	}
	if headroom < 20 || swapPercent >= 50 {
		return "warning"
	}
	return "normal"
}

func headroomScore(host HostSnapshot) int {
	scores := make([]float64, 0, 4)
	if host.TotalMemoryBytes > 0 && host.MemoryPressure != "unknown" {
		scores = append(scores, host.HeadroomPercent)
	}
	if host.SystemCPUPercent != nil {
		scores = append(scores, 100-clamp(*host.SystemCPUPercent, 0, 100))
	}
	if host.SwapTotalBytes > 0 {
		scores = append(scores, 100-percent(host.SwapUsedBytes, host.SwapTotalBytes))
	}
	thermalCap := map[string]float64{"nominal": 100, "fair": 70, "serious": 35, "critical": 10}
	if cap, ok := thermalCap[host.ThermalState]; ok {
		scores = append(scores, cap)
	}
	if len(scores) == 0 {
		return 0
	}
	score := scores[0]
	for _, candidate := range scores[1:] {
		score = min(score, candidate)
	}
	return int(math.Round(clamp(score, 0, 100)))
}

func capacityLabel(score int) string {
	if score < 15 {
		return "critical"
	}
	if score < 50 {
		return "constrained"
	}
	return "ample"
}

func percent(value, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(value) / float64(total) * 100
}

func saturatingSubtract(left, right uint64) uint64 {
	if right >= left {
		return 0
	}
	return left - right
}

func clamp(value, low, high float64) float64 { return min(max(value, low), high) }
func round1(value float64) float64           { return math.Round(value*10) / 10 }

func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copyOf := *value
	return &copyOf
}
