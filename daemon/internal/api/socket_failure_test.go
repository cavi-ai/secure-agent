package api

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServePreservesNonSocketPaths(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "daemon.sock")
			switch kind {
			case "file":
				if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing-target", path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // a wrongly successful bind must not hang this regression
			a := newTestAPI(path, testStore(t), &fakeKiller{}, func() Status { return Status{} })
			if err := a.Serve(ctx); err == nil {
				t.Error("non-socket path must refuse startup")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("existing %s was removed or replaced: %v", kind, err)
			}
			if kind == "file" {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "preserve" {
					t.Fatalf("existing file changed: %q, %v", data, err)
				}
			}
		})
	}
}

func TestServeListenerFailureClosesAcceptedStream(t *testing.T) {
	dir, err := os.MkdirTemp("", "sa-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "daemon.sock")
	listener, err := ListenUnixSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newTestAPI(path, testStore(t), &fakeKiller{}, func() Status { return Status{} })
	a.deltaHub = NewDeltaHub()
	defer a.deltaHub.Close()
	done := make(chan error, 1)
	go func() { done <- a.ServeListener(ctx, listener) }()
	client := unixClient(path)
	client.Timeout = 5 * time.Second
	response, err := client.Get("http://unix/events/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	readDone := make(chan struct{})
	go func() { io.Copy(io.Discard, response.Body); close(readDone) }()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("listener failure must be reported")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("listener failure did not stop the server")
	}
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted stream remained open after server exit")
	}
}
