package agents

import (
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
			start = boot.Add(time.Duration(ticks) * time.Second / time.Duration(hz))
		}
	}
	cpu := time.Duration(0)
	if len(rest) >= 13 && hz > 0 {
		userTicks, userErr := strconv.ParseUint(rest[11], 10, 64)
		systemTicks, systemErr := strconv.ParseUint(rest[12], 10, 64)
		if userErr == nil && systemErr == nil {
			cpu = time.Duration(userTicks+systemTicks) * time.Second / time.Duration(hz)
		}
	}
	return ppid, comm, start, cpu
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
