package resource

import "time"

type cpuTicks struct {
	User   uint64
	System uint64
	Idle   uint64
	Other  uint64
}

func cpuPercentFromTicks(previous, current cpuTicks) (float64, bool) {
	previousTotal := previous.User + previous.System + previous.Idle + previous.Other
	currentTotal := current.User + current.System + current.Idle + current.Other
	if currentTotal <= previousTotal || current.Idle < previous.Idle {
		return 0, false
	}
	totalDelta := currentTotal - previousTotal
	idleDelta := current.Idle - previous.Idle
	return round1(float64(totalDelta-idleDelta) / float64(totalDelta) * 100), true
}

func agentCPUPercentFromDurations(previous, current map[int32]time.Duration, elapsed time.Duration, logicalCPUs int) (float64, bool) {
	if previous == nil || elapsed <= 0 || logicalCPUs <= 0 {
		return 0, false
	}
	if len(previous) != len(current) {
		return 0, false
	}
	var delta time.Duration
	for pid, currentCPU := range current {
		previousCPU, ok := previous[pid]
		if !ok || currentCPU < previousCPU {
			return 0, false
		}
		delta += currentCPU - previousCPU
	}
	percent := float64(delta) / float64(elapsed) * 100 / float64(logicalCPUs)
	return round1(clamp(percent, 0, 100)), true
}

func cloneCPUTimes(values map[int32]time.Duration) map[int32]time.Duration {
	cloned := make(map[int32]time.Duration, len(values))
	for pid, value := range values {
		cloned[pid] = value
	}
	return cloned
}

func pidSet(values map[int32]time.Duration) map[int32]struct{} {
	set := make(map[int32]struct{}, len(values))
	for pid := range values {
		set[pid] = struct{}{}
	}
	return set
}
