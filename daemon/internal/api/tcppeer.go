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
// "ip.port" form), without self.
func ParseNetstatClientPIDs(out []byte, local string, self int) []int32 {
	var pids []int32
	for _, line := range bytes.Split(out, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) < 11 || string(f[3]) != local || string(f[5]) != "ESTABLISHED" {
			continue
		}
		for _, tok := range f[10:] {
			m := netstatPID.FindSubmatch(tok)
			if m == nil {
				continue
			}
			if n, err := strconv.Atoi(string(m[1])); err == nil && n > 0 && n != self {
				pids = append(pids, int32(n))
			}
			break
		}
	}
	return pids
}
