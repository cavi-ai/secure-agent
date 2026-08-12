package api

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type fakeKiller struct {
	killed int32
}

func (f *fakeKiller) Kill(pid int32) error {
	f.killed = pid
	return nil
}

func testStore(t *testing.T) *store.Store {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "test.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func unixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 2 * time.Second,
	}
}

func waitForSocket(t *testing.T, socketPath string) {
	for i := 0; i < 20; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socket %s not ready", socketPath)
}

func TestKillEndpointInvokesKiller(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	fk := &fakeKiller{}
	a := New(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":7}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("kill post: %v status=%v", err, resp.StatusCode)
	}
	if fk.killed != 7 {
		t.Fatalf("killer got pid %d, want 7", fk.killed)
	}
}
