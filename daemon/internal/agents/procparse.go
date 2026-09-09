package agents

import (
	"strconv"
	"strings"
	"time"
)

// parseProcStat parses /proc/<pid>/stat for ppid, comm, and start time.
// comm is in parens and may itself contain spaces/parens, so split at the LAST ')'.
func parseProcStat(s string, boot time.Time, hz int64) (int32, string, time.Time) {
	open := strings.IndexByte(s, '(')
	close_ := strings.LastIndexByte(s, ')')
	if open < 0 || close_ <= open {
		return 0, "", time.Time{}
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
	return ppid, comm, start
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
