package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
)

func TestPartialInspectionReportsCoverageAndPreservesBody(t *testing.T) {
	for _, size := range []int{scanCap, scanCap + 100} {
		b := bus.New(8)
		events := b.Subscribe()
		ps := NewProxyServer(0, b, nil, testProxyEngine(t, "block"))
		body := strings.Repeat("x", size)
		r := httptest.NewRequest("POST", "http://unknown.invalid/upload", strings.NewReader(body))
		r.ContentLength = -1 // also cover chunked uploads with no known size
		ps.inspectRequest(r, "unknown.invalid")
		forwarded, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(forwarded, []byte(body)) {
			t.Fatal("body changed")
		}
		select {
		case e := <-events:
			if size <= scanCap || e.Detail != "proxy-inspection-incomplete:body-limit" {
				t.Fatalf("unexpected finding: %s", e.Detail)
			}
		default:
			if size > scanCap {
				t.Fatal("partial inspection silently reported full coverage")
			}
		}
		b.Close()
	}
}

type failingBody struct{ closed bool }

func (*failingBody) Read([]byte) (int, error) { return 0, errors.New("fixture read failure") }
func (b *failingBody) Close() error           { b.closed = true; return nil }

func TestInspectionReadFailureIsVisibleAndBodyClosePreserved(t *testing.T) {
	b := bus.New(8)
	defer b.Close()
	events := b.Subscribe()
	ps := NewProxyServer(0, b, nil, testProxyEngine(t, "block"))
	r := httptest.NewRequest("POST", "http://unknown.invalid/upload", nil)
	body := &failingBody{}
	r.Body = body
	ps.inspectRequest(r, "unknown.invalid")
	select {
	case e := <-events:
		if e.Detail != "proxy-inspection-incomplete:body-read" {
			t.Fatal(e.Detail)
		}
	default:
		t.Fatal("read error discarded")
	}
	if _, err := io.ReadAll(r.Body); err == nil {
		t.Fatal("forwarding lost original body error")
	}
	r.Body.Close()
	if !body.closed {
		t.Fatal("original body closer lost")
	}
}

func TestTunnelClosesOnShutdown(t *testing.T) {
	tok := loadTestToken(t)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := upstream.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ps := NewProxyServer(0, bus.New(1), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ps.Serve(ctx) }()
	deadline := time.Now().Add(time.Second)
	var client net.Conn
	for time.Now().Before(deadline) {
		if ps.Port() != 0 {
			client, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ps.Port()), 100*time.Millisecond)
			if err == nil {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if client == nil {
		t.Fatal("listener unavailable")
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-SecureAgent-Proxy-Token: %s\r\n\r\n", upstream.Addr(), upstream.Addr(), tok)
	reader := bufio.NewReader(client)
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	var target net.Conn
	select {
	case target = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("not connected")
	}
	defer target.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung")
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("CONNECT survived shutdown")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("CONNECT remained open")
	}
}
