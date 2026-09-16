//go:build linux

package resource

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type linuxHostCollector struct {
	previousCPU       cpuTicks
	hasCPU            bool
	previousAgentCPU  map[int32]time.Duration
	previousSampledAt time.Time
}

func newPlatformHostSampler() hostSampler {
	collector := &linuxHostCollector{}
	return collector.sample
}

func (c *linuxHostCollector) sample(agentCPUTimes map[int32]time.Duration) rawHostSample {
	sampledAt := time.Now()
	raw := rawHostSample{LogicalCPUCount: runtime.NumCPU(), ThermalState: "unknown"}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		memory := parseLinuxMeminfo(string(data))
		raw.TotalMemoryBytes = memory.TotalMemoryBytes
		raw.FreeMemoryBytes = memory.FreeMemoryBytes
		raw.AvailableMemoryBytes = memory.AvailableMemoryBytes
		raw.AvailableMemoryKnown = memory.AvailableMemoryKnown
		raw.SwapTotalBytes = memory.SwapTotalBytes
		raw.SwapUsedBytes = memory.SwapUsedBytes
	}
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		if ticks, ok := parseLinuxCPUTicks(string(data)); ok {
			if c.hasCPU {
				if percent, valid := cpuPercentFromTicks(c.previousCPU, ticks); valid {
					raw.SystemCPUPercent = &percent
					if agent, aligned := agentCPUPercentFromDurations(c.previousAgentCPU, agentCPUTimes, sampledAt.Sub(c.previousSampledAt), raw.LogicalCPUCount); aligned {
						raw.AgentCPUPercent = &agent
					}
				}
			}
			c.previousCPU, c.hasCPU = ticks, true
		}
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			if value, err := strconv.ParseFloat(fields[0], 64); err == nil {
				raw.Load1 = &value
			}
		}
	}
	raw.ThermalState = readLinuxThermalState()
	c.previousAgentCPU = cloneCPUTimes(agentCPUTimes)
	c.previousSampledAt = sampledAt
	return raw
}

func parseLinuxMeminfo(input string) rawHostSample {
	values := make(map[string]uint64)
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	totalSwap := values["SwapTotal"]
	_, availableKnown := values["MemAvailable"]
	return rawHostSample{
		TotalMemoryBytes: values["MemTotal"], FreeMemoryBytes: values["MemFree"],
		AvailableMemoryBytes: values["MemAvailable"], AvailableMemoryKnown: availableKnown, SwapTotalBytes: totalSwap,
		SwapUsedBytes: saturatingSubtract(totalSwap, values["SwapFree"]),
	}
}

func parseLinuxCPUTicks(input string) (cpuTicks, bool) {
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != "cpu" {
			continue
		}
		values := make([]uint64, len(fields)-1)
		for i := 1; i < len(fields); i++ {
			value, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return cpuTicks{}, false
			}
			values[i-1] = value
		}
		other := values[1] + values[5] + values[6]
		if len(values) > 7 {
			other += values[7]
		}
		return cpuTicks{User: values[0], System: values[2], Idle: values[3] + values[4], Other: other}, true
	}
	return cpuTicks{}, false
}

func readLinuxThermalState() string {
	paths, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	maximum := int64(0)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err == nil && value > maximum {
			maximum = value
		}
	}
	if maximum == 0 {
		return "unknown"
	}
	return linuxThermalState(maximum)
}

func linuxThermalState(milliCelsius int64) string {
	switch {
	case milliCelsius >= 100_000:
		return "critical"
	case milliCelsius >= 90_000:
		return "serious"
	case milliCelsius >= 80_000:
		return "fair"
	default:
		return "nominal"
	}
}
