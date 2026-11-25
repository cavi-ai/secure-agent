package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func startCollectorServer(t *testing.T, timeouts serverTimeouts) string {
	t.Helper()
	dir := t.TempDir()
	c := &Collector{
		cfg:   Config{Addr: "127.0.0.1:0", Secrets: map[string]string{"n1": "s3cret"}, StoreDir: dir},
		store: NewStore(dir),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(ln.Addr().String(), newMux(c), timeouts)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestServerClosesStalledHeaderConnection(t *testing.T) {
	addr := startCollectorServer(t, serverTimeouts{
		ReadHeader: 200 * time.Millisecond,
		Read:       time.Second,
		Write:      time.Second,
		Idle:       time.Second,
	})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("POST /hooks/secure-agent HTTP/1.1\r\nHost: x\r\nX-Partial: ")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(1500 * time.Millisecond))
	_, err = io.ReadAll(conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server still holding stalled connection after %v", time.Since(start))
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("connection closed after %v, want under 1s", d)
	}
}

func TestServerAcceptsLargeSignedEnvelope(t *testing.T) {
	addr := startCollectorServer(t, defaultServerTimeouts)
	payload, _ := json.Marshal(map[string]string{"pad": strings.Repeat("a", 1536<<10)})
	body, _ := json.Marshal(Envelope{
		NodeID: "n1", Kind: "flag", TS: time.Now().UTC().Format(time.RFC3339Nano),
		Version: "v0.9.0", Payload: payload,
	})
	req, _ := http.NewRequest("POST", "http://"+addr+"/hooks/secure-agent", bytes.NewReader(body))
	req.Header.Set("X-SecureAgent-Node", "n1")
	req.Header.Set("X-SecureAgent-Signature", sign(t, "s3cret", body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}

func TestServerServesOverview(t *testing.T) {
	addr := startCollectorServer(t, defaultServerTimeouts)
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}

func TestServerRejectsOversizedHeaders(t *testing.T) {
	addr := startCollectorServer(t, defaultServerTimeouts)
	req, _ := http.NewRequest("GET", "http://"+addr+"/healthz", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 128<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status %d, want 431", resp.StatusCode)
	}
}
