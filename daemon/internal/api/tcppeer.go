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
	for _, line := range bytes.Split(out, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) < 11 || string(f[3]) != local || string(f[5]) != "ESTABLISHED" {
			continue
		}
		// Only the pid column identifies the owner; never fall back to epid.
		if n, err := strconv.ParseInt(string(f[10]), 10, 32); err == nil {
			if n > 0 && int(n) != self {
				pids = append(pids, int32(n))
			}
			continue
		}
		for _, tok := range f[10:] {
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
