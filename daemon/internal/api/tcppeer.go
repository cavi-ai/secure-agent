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
// "ip.port" form), without self. The header locates the pid: some releases
// print rxbytes and txbytes before it and some do not, and the column is
// either a numeric "pid" followed by epid or "process:pid".
func ParseNetstatClientPIDs(out []byte, local string, self int) []int32 {
	var pids []int32
	col, named := -1, false
	for _, line := range bytes.Split(out, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) > 0 && string(f[0]) == "Proto" {
			col, named = netstatPIDColumn(f)
			continue
		}
		if col < 0 || len(f) <= col || string(f[3]) != local || string(f[5]) != "ESTABLISHED" {
			continue
		}
		if n := netstatClientPID(f[col:], named); n > 0 && n != int64(self) {
			pids = append(pids, int32(n))
		}
	}
	return pids
}

// netstatPIDColumn returns the data field index of the pid column and
// whether it is process:pid, or -1. "Local Address" and "Foreign Address"
// are two header words for one data field.
func netstatPIDColumn(header [][]byte) (int, bool) {
	col := 0
	for i, h := range header {
		if string(h) == "Address" && i > 0 && (string(header[i-1]) == "Local" || string(header[i-1]) == "Foreign") {
			continue
		}
		switch string(h) {
		case "pid":
			return col, false
		case "process:pid":
			return col, true
		}
		col++
	}
	return -1, false
}

// netstatClientPID reads the pid from the fields starting at the pid
// column: the field itself, or the first token ending in ":pid" when the
// process name before it has spaces. Only the pid column names the owner;
// epid never stands in for it.
func netstatClientPID(cols [][]byte, named bool) int64 {
	tok := cols[0]
	if named {
		tok = nil
		for _, c := range cols {
			if m := netstatPID.FindSubmatch(c); m != nil {
				tok = m[1]
				break
			}
		}
	}
	n, err := strconv.ParseInt(string(tok), 10, 32)
	if err != nil {
		return 0
	}
	return n
}
