package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
)

func TestCancellationClosesHijackedConnections(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		t.Run(fmt.Sprintf("inspect=%t", inspect), func(t *testing.T) {
			up, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer up.Close()
			peers := make(chan net.Conn, 1)
			if !inspect {
				go func() {
					c, err := up.Accept()
					if err == nil {
						peers <- c
					}
				}()
			}
			b := bus.New(4)
			defer b.Close()
			dir := t.TempDir()
			ca, err := NewCAManager(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
			if err != nil {
				t.Fatal(err)
			}
			ps := NewProxyServer(0, b, ca, nil)
			handlerDone := make(chan struct{})
			ps.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(handlerDone)
				if inspect {
					ps.handleConnect(w, r)
				} else {
					ps.tunnel(w, r)
				}
			})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- ps.serveListener(ctx, ln) }()
			c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", up.Addr(), up.Addr()); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("CONNECT: %v %v", resp, err)
			}
			var peer net.Conn
			if !inspect {
				select {
				case peer = <-peers:
					defer peer.Close()
				case <-time.After(5 * time.Second):
					t.Fatal("upstream not connected")
				}
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("service did not stop")
			}
			var one [1]byte
			if n, err := c.Read(one[:]); n != 0 || err == nil {
				t.Fatalf("client remained open: %d %v", n, err)
			}
			if peer != nil {
				_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := peer.Read(one[:]); err != io.EOF {
					t.Fatalf("upstream remained open: %v", err)
				}
			}
			select {
			case <-handlerDone:
			case <-time.After(5 * time.Second):
				t.Fatal("hijacked handler did not exit")
			}
			late, remote := net.Pipe()
			defer remote.Close()
			if ps.ownConnection(ctx, late) {
				t.Fatal("connection admitted after shutdown")
			}
		})
	}
}
