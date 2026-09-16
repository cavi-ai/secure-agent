package api

// Two daemons overlapping on one socket path: the old instance's shutdown
// must NOT unlink the new instance's live socket. Regression for the race
// where a healthy daemon ended up listening on an unlinked path — running,
// but unreachable (popover: "Disconnected").
import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestServeShutdownDoesNotUnlinkSuccessorsSocket(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_test_race_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	statusFn := func() Status { return Status{Running: true} }

	// Daemon A binds, then Daemon B takes over the same path (B's Serve
	// removes the "stale" file and binds — the normal takeover).
	a1 := New(sock, st, &fakeKiller{}, statusFn)
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- a1.Serve(ctx1) }()
	waitForSocket(t, sock)

	a2 := New(sock, st, &fakeKiller{}, statusFn)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- a2.Serve(ctx2) }()
	waitForSocket(t, sock)

	// A exits. The old cleanup would unlink the path wholesale; B's socket
	// must survive.
	cancel1()
	if err := <-done1; err != nil {
		t.Fatalf("daemon A serve: %v", err)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("successor's socket was unlinked by the old daemon's shutdown: %v", err)
	}
	resp, err := unixClient(sock).Get("http://unix/status")
	if err != nil {
		t.Fatalf("successor daemon must still answer on its socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("successor status = %d", resp.StatusCode)
	}
}
