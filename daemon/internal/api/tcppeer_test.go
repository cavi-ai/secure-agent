package api

import (
	"fmt"
	"testing"
)

func TestParseNetstatClientPIDsLegacy(t *testing.T) {
	// Apple's legacy netstat format has separate pid and epid columns.
	const header = "Proto Recv-Q Send-Q Local Address Foreign Address (state) rxbytes txbytes rhiwat shiwat pid epid state options\n"
	for _, tc := range []struct {
		name, pid, epid, want string
	}{
		{"client", "7533", "0", "[7533]"},
		{"self", "31607", "7533", "[]"},
		{"no owner", "0", "7533", "[]"},
		{"negative", "-1", "7533", "[]"},
		{"overflow", "2147483648", "7533", "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := header + fmt.Sprintf("tcp4 0 0 127.0.0.1.64809 127.0.0.1.8443 ESTABLISHED 2199 4606 513160 146988 %s %s 00102 00000008\n", tc.pid, tc.epid)
			if got := fmt.Sprint(ParseNetstatClientPIDs([]byte(out), "127.0.0.1.64809", 31607)); got != tc.want {
				t.Fatalf("pids = %s, want %s", got, tc.want)
			}
		})
	}
}
