//go:build linux

package collect

import (
	"os"
	"testing"
)

func TestHexToIPv4LittleEndian(t *testing.T) {
	// 0100007F = 127.0.0.1 (little-endian on the wire in /proc/net/tcp)
	if got := hexToIP("0100007F"); got != "127.0.0.1" {
		t.Fatalf("hexToIP v4 = %q, want 127.0.0.1", got)
	}
	if got := hexToIP("5708A8C0"); got != "192.168.8.87" {
		t.Fatalf("hexToIP v4 = %q, want 192.168.8.87", got)
	}
}

func TestHexToIPv6WordSwapped(t *testing.T) {
	// ::1 in /proc/net/tcp6 is 16 zero bytes + 01.
	got := hexToIP("00000000000000000000000001000000")
	if got != "::1" {
		t.Fatalf("hexToIP v6 = %q, want ::1", got)
	}
}

func TestHexToIPRejectsGarbage(t *testing.T) {
	if got := hexToIP("xyz"); got != "" {
		t.Fatalf("hexToIP garbage = %q, want empty", got)
	}
	if got := hexToIP("0100007"); got != "" { // odd length
		t.Fatalf("hexToIP odd length = %q, want empty", got)
	}
}

func TestParseProcNetTCPFiltersToEstablished(t *testing.T) {
	t.Parallel()
	// Fixture: one LISTEN (0A), one ESTABLISHED (01), one TIME_WAIT (06).
	// Only the ESTABLISHED row may appear.
	dir := t.TempDir()
	p := dir + "/tcp"
	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0        111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:ABCD 5708A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0        222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:DEF0 5708A8C0:01BB 06 00000000:00000000 00:00000000 00000000  1000        0        333 1 0000000000000000 100 0 0 10 0
`
	if err := writeFile(p, fixture); err != nil {
		t.Fatal(err)
	}
	conns := parseProcNetTCP(p)
	if len(conns) != 1 {
		t.Fatalf("expected exactly 1 established conn, got %d (%v)", len(conns), conns)
	}
	rc := conns["222"]
	if rc.host != "192.168.8.87" || rc.port != 443 {
		t.Fatalf("established conn = %+v, want 192.168.8.87:443", rc)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
