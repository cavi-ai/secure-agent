package api

import (
	"bytes"
	"strconv"
)

// ParseLsofPIDs returns the pids in `lsof -Fp` output, without self.
func ParseLsofPIDs(out []byte, self int) []int32 {
	var pids []int32
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(line) < 2 || line[0] != 'p' {
			continue
		}
		n, err := strconv.Atoi(string(line[1:]))
		if err != nil || n <= 0 || n == self {
			continue
		}
		pids = append(pids, int32(n))
	}
	return pids
}
