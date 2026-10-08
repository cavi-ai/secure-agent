package api

import (
	"bytes"
	"regexp"
	"strconv"
)

// netstatPID is the process:pid column of `netstat -anv`; the process name
// is truncated and may contain spaces, so the pid ends the first token that
// carries one.
var netstatPID = regexp.MustCompile(`:(\d+)$`)

// ParseNetstatClientPIDs returns the pids of established TCP connections in
// `netstat -anv -p tcp` output whose local address is local (netstat's
// "ip.port" form), without self. Older macOS versions emit a numeric pid
// followed by epid; newer versions emit process:pid instead.
func ParseNetstatClientPIDs(out []byte, local string, self int) []int32 {
	var pids []int32
	pidColumn := -1
	namedPID := false
	for _, line := range bytes.Split(out, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) > 0 && string(f[0]) == "Proto" {
			pidColumn = -1
			for i, column := 0, 0; i < len(f); i, column = i+1, column+1 {
				// Each address heading spans two words but one data column.
				if (string(f[i]) == "Local" || string(f[i]) == "Foreign") && i+1 < len(f) && string(f[i+1]) == "Address" {
					i++
				}
				switch string(f[i]) {
				case "pid", "process:pid":
					pidColumn, namedPID = column, string(f[i]) == "process:pid"
				}
			}
			continue
		}
		if pidColumn < 6 || len(f) <= pidColumn || (string(f[0]) != "tcp4" && string(f[0]) != "tcp6") || string(f[3]) != local || string(f[5]) != "ESTABLISHED" {
			continue
		}
		// Only the pid column identifies the owner; never fall back to epid.
		if !namedPID {
			if n, err := strconv.ParseInt(string(f[pidColumn]), 10, 32); err == nil && n > 0 && int(n) != self {
				pids = append(pids, int32(n))
			}
			continue
		}
		for _, tok := range f[pidColumn:] {
			m := netstatPID.FindSubmatch(tok)
			if m == nil {
				continue
			}
			if n, err := strconv.ParseInt(string(m[1]), 10, 32); err == nil && n > 0 && int(n) != self {
				pids = append(pids, int32(n))
			}
			break
		}
	}
	return pids
}
