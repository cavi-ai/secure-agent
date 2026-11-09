package localservice

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestNativeListenerInventoryFindsDynamicPort(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_LISTENER_INVENTORY") != "1" {
		t.Skip("opt-in native lsof inventory proof")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	inventory := DiscoverListeners(context.Background())
	for _, found := range inventory.Listeners {
		if found.PID == os.Getpid() && found.Address == listener.Addr().String() && found.Endpoint == "http://"+listener.Addr().String() && found.Binding == "loopback" {
			t.Logf("native inventory found this test process's dynamic loopback listener; state=%s truncated=%t", inventory.State, inventory.Truncated)
			return
		}
	}
	t.Fatalf("native dynamic listener absent; state=%s truncated=%t visible=%d", inventory.State, inventory.Truncated, len(inventory.Listeners))
}
