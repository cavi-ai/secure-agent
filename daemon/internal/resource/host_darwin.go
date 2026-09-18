//go:build darwin

package resource

import (
	"context"
	"encoding/binary"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type darwinHostCollector struct {
	previousCPU       cpuTicks
	hasCPU            bool
	previousAgentCPU  map[int32]time.Duration
	previousSampledAt time.Time
}

func newPlatformHostSampler() hostSampler {
	collector := &darwinHostCollector{}
	return collector.sample
}

func (c *darwinHostCollector) sample(agentCPUTimes map[int32]time.Duration) rawHostSample {
	sampledAt := time.Now()
	raw := rawHostSample{LogicalCPUCount: runtime.NumCPU(), ThermalState: "unknown"}
	if total, err := unix.SysctlUint64("hw.memsize"); err == nil {
		raw.TotalMemoryBytes = total
	}
	if output, err := runHostCommand("/usr/bin/vm_stat"); err == nil {
		raw.FreeMemoryBytes, raw.AvailableMemoryBytes, raw.CompressedMemoryBytes, raw.AvailableMemoryKnown = parseDarwinVMStat(string(output))
	}
	if swap, err := unix.SysctlRaw("vm.swapusage"); err == nil {
		raw.SwapTotalBytes, raw.SwapUsedBytes = parseDarwinSwapUsage(swap)
	}
	if ticks, ok := readDarwinCPUTicks(); ok {
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
	if raw.SystemCPUPercent == nil {
		if output, err := runHostCommand("/bin/ps", "-A", "-o", "pid=", "-o", "%cpu="); err == nil {
			if system, agent, ok := parseDarwinProcessCPU(string(output), raw.LogicalCPUCount, pidSet(agentCPUTimes)); ok {
				raw.SystemCPUPercent, raw.AgentCPUPercent = &system, &agent
			}
		}
	}
	if output, err := runHostCommand("/usr/bin/pmset", "-g", "therm"); err == nil {
		raw.ThermalState = parseDarwinThermalState(string(output))
	}
	c.previousAgentCPU = cloneCPUTimes(agentCPUTimes)
	c.previousSampledAt = sampledAt
	return raw
}

func runHostCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

var vmStatPageSize = regexp.MustCompile(`page size of ([0-9]+) bytes`)

func parseDarwinVMStat(output string) (free, available, compressed uint64, availableKnown bool) {
	pageSize := uint64(4096)
	if match := vmStatPageSize.FindStringSubmatch(output); len(match) == 2 {
		if parsed, err := strconv.ParseUint(match[1], 10, 64); err == nil {
			pageSize = parsed
		}
	}
	values := make(map[string]uint64)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), ".")
		if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
			values[strings.TrimSpace(parts[0])] = parsed
		}
	}
	freePages := values["Pages free"]
	availablePages := freePages + values["Pages inactive"] + values["Pages speculative"]
	_, freeKnown := values["Pages free"]
	_, inactiveKnown := values["Pages inactive"]
	return freePages * pageSize, availablePages * pageSize, values["Pages occupied by compressor"] * pageSize, freeKnown && inactiveKnown
}

func parseDarwinSwapUsage(raw []byte) (total, used uint64) {
	if len(raw) < 24 {
		return 0, 0
	}
	return binary.LittleEndian.Uint64(raw[0:8]), binary.LittleEndian.Uint64(raw[16:24])
}

func readDarwinCPUTicks() (cpuTicks, bool) {
	raw, err := unix.SysctlRaw("kern.cp_time")
	if err != nil {
		return cpuTicks{}, false
	}
	values := make([]uint64, 5)
	switch {
	case len(raw) >= 40:
		for i := range values {
			values[i] = binary.LittleEndian.Uint64(raw[i*8 : i*8+8])
		}
	case len(raw) >= 20:
		for i := range values {
			values[i] = uint64(binary.LittleEndian.Uint32(raw[i*4 : i*4+4]))
		}
	default:
		return cpuTicks{}, false
	}
	return cpuTicks{User: values[0], Other: values[1] + values[4], System: values[2], Idle: values[3]}, true
}

func parseDarwinProcessCPU(output string, logicalCPUs int, agentPIDs map[int32]struct{}) (system, agent float64, ok bool) {
	if logicalCPUs <= 0 {
		return 0, 0, false
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		pid, pidErr := strconv.ParseInt(fields[0], 10, 32)
		value, valueErr := strconv.ParseFloat(fields[1], 64)
		if pidErr != nil || valueErr != nil || value < 0 {
			continue
		}
		system += value
		if _, isAgent := agentPIDs[int32(pid)]; isAgent {
			agent += value
		}
		ok = true
	}
	if !ok {
		return 0, 0, false
	}
	return round1(clamp(system/float64(logicalCPUs), 0, 100)), round1(clamp(agent/float64(logicalCPUs), 0, 100)), true
}

func parseDarwinThermalState(output string) string {
	minimum := 101
	found := false
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || !strings.Contains(parts[0], "Limit") {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err == nil {
			minimum, found = min(minimum, value), true
		}
	}
	if !found {
		return "unknown"
	}
	switch {
	case minimum >= 90:
		return "nominal"
	case minimum >= 75:
		return "fair"
	case minimum >= 50:
		return "serious"
	default:
		return "critical"
	}
}
