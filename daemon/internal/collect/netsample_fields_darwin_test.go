//go:build darwin

package collect

import "testing"

func TestSocketFieldsPreserveBothEndpoints(t *testing.T) {
	snapshot := parseSocketFields([]byte("p777\ncPython app\nf4\ntIPv6\nn[::1]:50001->[::1]:11434\nf5\ntIPv6\nn[::1]:50002->[::1]:11434\n"))
	if snapshot.State != "available" || len(snapshot.Connections) != 2 {
		t.Fatalf("snapshot: %+v", snapshot)
	}
	if snapshot.Connections[0].LocalPort == snapshot.Connections[1].LocalPort || snapshot.Connections[0].Host != "::1" || snapshot.Connections[0].PID != 777 {
		t.Fatalf("connections: %+v", snapshot.Connections)
	}
	if bad := parseSocketFields([]byte("p12\nnmalformed\n")); bad.State != "partial" {
		t.Fatalf("malformed snapshot: %+v", bad)
	}
}
