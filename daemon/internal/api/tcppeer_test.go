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

// Releases that print rxbytes and txbytes only with -b put the pid two
// fields earlier under -anv; the socket state after epid ("00102") must
// never be read as a pid.
func TestParseNetstatClientPIDsWithoutByteCounts(t *testing.T) {
	out := []byte(`Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rhiwat  shiwat    pid   epid  state  options           gencnt    flags   flags1 usecnt rtncnt  fltrs
tcp4       0      0  127.0.0.1.8443         127.0.0.1.49300        ESTABLISHED  406208  146988  31607      0 00102 0000000c 0000000000b27dec 00000080 01000800      2      0 000000
tcp4       0      0  127.0.0.1.49300        127.0.0.1.8443         ESTABLISHED  513160  146988   4719      0 00102 00000008 0000000000b27deb 00000080 04000900      2      0 000000
`)
	if got := fmt.Sprint(ParseNetstatClientPIDs(out, "127.0.0.1.49300", 31607)); got != "[4719]" {
		t.Fatalf("pids = %s, want [4719]", got)
	}
	if got := ParseNetstatClientPIDs(out, "127.0.0.1.8443", 31607); len(got) != 0 {
		t.Fatalf("pids for the daemon's own end = %v, want none", got)
	}
}

func TestParseNetstatClientPIDsNeedsAPIDHeader(t *testing.T) {
	out := []byte("tcp4 0 0 127.0.0.1.49300 127.0.0.1.8443 ESTABLISHED 513160 146988 4719 0 00102 00000008\n")
	if got := ParseNetstatClientPIDs(out, "127.0.0.1.49300", 31607); len(got) != 0 {
		t.Fatalf("pids without a header = %v, want none", got)
	}
}
