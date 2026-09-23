//go:build darwin

package api

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
)

// The console listener's peer lookup names the process holding the client
// end of a loopback connection: a curl child, not this test process.
func TestTCPClientPIDNamesTheConnectingProcess(t *testing.T) {
	got := make(chan int32, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pid, err := TCPClientPID(r.RemoteAddr)
		if err != nil {
			t.Errorf("TCPClientPID(%s): %v", r.RemoteAddr, err)
		}
		got <- pid
	}))
	defer srv.Close()

	cmd := exec.Command("/usr/bin/curl", "-s", "-o", "/dev/null", "--max-time", "10", srv.URL)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := <-got
	_ = cmd.Wait()
	if pid != int32(cmd.Process.Pid) {
		t.Fatalf("TCPClientPID = %d, want the curl child %d", pid, cmd.Process.Pid)
	}
}
