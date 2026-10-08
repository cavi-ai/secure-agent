package api

import (
	"fmt"
	"testing"
)

func TestParseNetstatClientPIDsLegacy(t *testing.T) {
	// Apple's legacy netstat format has separate pid and epid columns.
	for _, layout := range []struct{ name, byteHeaders, byteValues string }{
		{"with bytes", "rxbytes txbytes ", "2199 4606 "},
		{"without bytes", "", ""},
	} {
		t.Run(layout.name, func(t *testing.T) {
			header := "Proto Recv-Q Send-Q Local Address Foreign Address (state) " + layout.byteHeaders + "rhiwat shiwat pid epid state options\n"
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
					out := header + fmt.Sprintf("tcp4 0 0 127.0.0.1.64809 127.0.0.1.8443 ESTABLISHED %s513160 146988 %s %s 00102 00000008\n", layout.byteValues, tc.pid, tc.epid)
					if got := fmt.Sprint(ParseNetstatClientPIDs([]byte(out), "127.0.0.1.64809", 31607)); got != tc.want {
						t.Fatalf("pids = %s, want %s", got, tc.want)
					}
				})
			}
		})
	}
}

func TestParseNetstatClientPIDsRequiresOwnerHeader(t *testing.T) {
	for _, header := range []string{"", "Proto Recv-Q Send-Q Local Address Foreign Address (state) rhiwat shiwat epid options\n"} {
		out := header + "tcp4 0 0 127.0.0.1.64809 127.0.0.1.8443 ESTABLISHED 513160 146988 7533 0 00102 00000008\n"
		if got := ParseNetstatClientPIDs([]byte(out), "127.0.0.1.64809", 31607); len(got) != 0 {
			t.Fatalf("pids without an owner header = %v", got)
		}
	}
}

func TestParseNetstatClientPIDsNamedWithoutBytes(t *testing.T) {
	const header = "Proto Recv-Q Send-Q Local Address Foreign Address (state) rhiwat shiwat process:pid state options\n"
	for _, tc := range []struct{ owner, want string }{
		{"Brave Browser He:7533", "[7533]"},
		{"secure-agentd:31607", "[]"},
		{"curl:0", "[]"},
		{"curl:2147483648", "[]"},
	} {
		out := header + "tcp4 0 0 127.0.0.1.64809 127.0.0.1.8443 ESTABLISHED 513160 146988 " + tc.owner + " 00102 00000008\n"
		if got := fmt.Sprint(ParseNetstatClientPIDs([]byte(out), "127.0.0.1.64809", 31607)); got != tc.want {
			t.Fatalf("owner %q: pids = %s, want %s", tc.owner, got, tc.want)
		}
	}
}
