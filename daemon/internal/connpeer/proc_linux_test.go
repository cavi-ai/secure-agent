//go:build linux

package connpeer

import (
	"net"
	"os/exec"
	"testing"
	"time"
)

// A child process connected to this process's listener is named as the
// client of its connection.
func TestClientPIDNamesTheConnectedProcess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cmd := exec.Command("python3", "-c", "import socket,sys,time;s=socket.create_connection(('127.0.0.1',int(sys.argv[1])));time.sleep(10)", strconvPort(ln))
	if err := cmd.Start(); err != nil {
		t.Skip("python3 unavailable:", err)
	}
	defer cmd.Process.Kill()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pid, err := ClientPID(conn.RemoteAddr().String())
	if err != nil || int(pid) != cmd.Process.Pid {
		t.Fatalf("ClientPID = %d, %v; want %d", pid, err, cmd.Process.Pid)
	}
	if _, err := ClientPID("127.0.0.1:1"); err == nil {
		t.Fatal("named a client for an address with no socket")
	}
}

func strconvPort(ln net.Listener) string {
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}
