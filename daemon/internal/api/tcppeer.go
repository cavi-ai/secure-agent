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
// "ip.port" form), without self. The header names the pid column: newer
// netstat prints "process:pid", older releases a bare "pid" column.
func ParseNetstatClientPIDs(out []byte, local string, self int) []int32 {
	var pids []int32
	named := true
	for _, line := range bytes.Split(out, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) > 0 && string(f[0]) == "Proto" {
			named = bytes.Contains(line, []byte("process:pid"))
			continue
		}
		if len(f) < 11 || string(f[3]) != local || string(f[5]) != "ESTABLISHED" {
			continue
		}
		if n := netstatClientPID(f[10:], named); n > 0 && n != self {
			pids = append(pids, int32(n))
		}
	}
	return pids
}

// netstatClientPID reads the pid from a line's fields after shiwat: the
// first token ending ":pid" when the column is process:pid, else the field
// itself.
func netstatClientPID(cols [][]byte, named bool) int {
	if !named {
		n, _ := strconv.Atoi(string(cols[0]))
		return n
	}
	for _, tok := range cols {
		if m := netstatPID.FindSubmatch(tok); m != nil {
			n, _ := strconv.Atoi(string(m[1]))
			return n
		}
	}
	return 0
}
