//go:build linux

package daemon

import (
	"net"
	"os/exec"
	"testing"
	"time"
)

func TestInferenceClientPIDUsesLinuxSocketOwner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	child := exec.Command("python3", "-c", "import socket,sys,time;host,port=sys.argv[1].rsplit(':',1);s=socket.create_connection((host,int(port)));time.sleep(10)", listener.Addr().String())
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	pid, err := inferenceClientPID(connection.RemoteAddr().String())
	if err != nil || pid != int32(child.Process.Pid) {
		t.Fatalf("client PID %d, expected %d: %v", pid, child.Process.Pid, err)
	}
}
