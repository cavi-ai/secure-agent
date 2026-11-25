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
		store: openTestStore(t, dir),
	}
	return serveCollector(t, c, timeouts)
}

func serveCollector(t *testing.T, c *Collector, timeouts serverTimeouts) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(ln.Addr().String(), c, timeouts)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestServerClosesStalledHeaderConnection(t *testing.T) {
	addr := startCollectorServer(t, serverTimeouts{
		ReadHeader: 200 * time.Millisecond,
		Read:       5 * time.Second,
		Write:      time.Second,
		Idle:       time.Second,
	})
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("POST /hooks/secure-agent HTTP/1.1\r\nHost: x\r\nX-Partial: ")); err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server still holding stalled connection after %v", time.Since(start))
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
}

type delayedQueryLog struct {
	envelopeLog
	delay time.Duration
}

func (l delayedQueryLog) Query(nodeID string, kinds map[string]bool, limit int) []envelopeFile {
	time.Sleep(l.delay)
	return l.envelopeLog.Query(nodeID, kinds, limit)
}

func TestServerServesNodeEventsAfterSlowQuery(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir)
	if err := store.Append(Envelope{NodeID: "n1", Kind: "flag", Payload: json.RawMessage(`{"rule":"test-rule"}`)}); err != nil {
		t.Fatal(err)
	}
	timeouts := defaultServerTimeouts
	timeouts.Write = 250 * time.Millisecond
	store.log = delayedQueryLog{envelopeLog: store.log, delay: 2 * timeouts.Write}
	c := &Collector{
		cfg:   Config{Addr: "127.0.0.1:0", Secrets: map[string]string{"n1": "s3cret"}, StoreDir: dir},
		store: store,
	}
	addr := serveCollector(t, c, timeouts)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/nodes/n1/events?kind=flag&limit=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var events []envelopeFile
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Envelope.Kind != "flag" || string(events[0].Envelope.Payload) != `{"rule":"test-rule"}` {
		t.Fatalf("events = %+v, want the stored flag", events)
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
