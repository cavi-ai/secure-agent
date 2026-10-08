package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
)

func TestServingRetryAdmitsNewConnections(t *testing.T) {
	b := bus.New(4)
	defer b.Close()
	ps := NewProxyServer(0, b, nil, nil)
	accepted := make(chan context.Context, 1)
	ps.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { accepted <- r.Context(); ps.tunnel(w, r) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listen := func() net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	first := listen()
	done := make(chan error, 1)
	go func() { done <- ps.serveListener(ctx, first) }()
	// A completed HTTP request synchronizes the first serving generation.
	c, err := net.DialTimeout("tcp", first.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: invalid\r\nConnection: close\r\n\r\n")
	old := <-accepted
	_, _ = http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	_ = c.Close()
	_ = first.Close() // unexpected listener failure, not intentional Shutdown
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("listener failure not reported")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed serve did not exit")
	}
	if old.Err() == nil {
		t.Fatal("old serving context survived failure")
	}
	second := listen()
	defer second.Close()
	go func() { done <- ps.serveListener(ctx, second) }()
	up := listen()
	defer up.Close()
	peer := make(chan net.Conn, 1)
	go func() {
		c, err := up.Accept()
		if err == nil {
			peer <- c
		}
	}()
	c, err = net.DialTimeout("tcp", second.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", up.Addr(), up.Addr())
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("recovered CONNECT rejected: %v %v", resp, err)
	}
	select {
	case p := <-peer:
		defer p.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no recovered upstream")
	}
	late, remote := net.Pipe()
	defer remote.Close()
	if ps.ownConnection(old, late) {
		t.Fatal("obsolete handler escaped into recovered generation")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recovered serve did not stop")
	}
}
