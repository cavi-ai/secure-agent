package agents

import (
	"math"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

// parseProcStat parses /proc/<pid>/stat for ppid, comm, start time, and
// cumulative user plus system CPU time.
// comm is in parens and may itself contain spaces/parens, so split at the LAST ')'.
func parseProcStat(s string, boot time.Time, hz int64) (int32, string, time.Time, time.Duration) {
	open := strings.IndexByte(s, '(')
	close_ := strings.LastIndexByte(s, ')')
	if open < 0 || close_ <= open {
		return 0, "", time.Time{}, 0
	}
	comm := s[open+1 : close_]
	// Fields after ')' start at field 3 (state); field 4 is ppid; field 22 is starttime.
	rest := strings.Fields(s[close_+1:])
	ppid := int32(0)
	if len(rest) >= 2 {
		if v, err := strconv.ParseInt(rest[1], 10, 32); err == nil {
			ppid = int32(v)
		}
	}
	start := time.Time{}
	if len(rest) >= 20 && !boot.IsZero() && hz > 0 {
		if ticks, err := strconv.ParseUint(rest[19], 10, 64); err == nil {
			if elapsed, ok := processTicksDuration(ticks, uint64(hz)); ok {
				start = boot.Add(elapsed)
			}
		}
	}
	cpu := time.Duration(0)
	if len(rest) >= 13 && hz > 0 {
		userTicks, userErr := strconv.ParseUint(rest[11], 10, 64)
		systemTicks, systemErr := strconv.ParseUint(rest[12], 10, 64)
		if userErr == nil && systemErr == nil {
			if total, overflow := bits.Add64(userTicks, systemTicks, 0); overflow == 0 {
				cpu, _ = processTicksDuration(total, uint64(hz))
			}
		}
	}
	return ppid, comm, start, cpu
}

// Split off the whole seconds before scaling ticks to nanoseconds.
func processTicksDuration(ticks, hz uint64) (time.Duration, bool) {
	seconds, remainder := ticks/hz, ticks%hz
	const nanosPerSecond = uint64(time.Second)
	if seconds > math.MaxInt64/nanosPerSecond {
		return 0, false
	}
	hi, lo := bits.Mul64(remainder, nanosPerSecond)
	fraction, _ := bits.Div64(hi, lo, hz)
	total := seconds*nanosPerSecond + fraction
	if total > math.MaxInt64 {
		return 0, false
	}
	return time.Duration(total), true
}

func parseProcStatm(s string, pageSize uint64) uint64 {
	fields := strings.Fields(s)
	if len(fields) < 2 || pageSize == 0 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * pageSize
}
