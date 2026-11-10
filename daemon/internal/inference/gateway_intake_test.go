package inference

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// A rejected request must not make net/http drain an unfinished body before
// returning the refusal or closing the connection.
func TestGatewayRejectsUnfinishedUploads(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{"missing-key", 401},
		{"foreign-origin", 403},
		{"foreign-host", 403},
		{"admin", 403},
		{"capacity", 503},
		{"oversized", 413},
		{"chunked-missing-key", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				http.Error(w, "unexpected backend request", 500)
			}))
			defer upstream.Close()
			m, server, key := testGateway(t, upstream.URL)
			r := gatewayRequest(t, server.URL, key, "")
			length := "1024"
			switch tc.name {
			case "missing-key", "chunked-missing-key":
				r.Header.Del("Authorization")
			case "foreign-origin":
				r.Header.Set("Origin", "https://example.invalid")
			case "foreign-host":
				r.Host = "example.invalid"
			case "admin":
				r.URL.Path = "/api/pull"
			case "capacity":
				for range maxActiveRequests {
					if !m.reserve() {
						t.Fatal("could not fill gateway admission slots")
					}
					defer m.release()
				}
			case "oversized":
				length = strconv.Itoa(16<<20 + 1)
			}
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\n", r.URL.Path, r.Host); err != nil {
				t.Fatal(err)
			}
			if err := r.Header.Write(conn); err != nil {
				t.Fatal(err)
			}
			if tc.name == "chunked-missing-key" {
				_, err = fmt.Fprint(conn, "Transfer-Encoding: chunked\r\n\r\n400\r\nx")
			} else {
				_, err = fmt.Fprintf(conn, "Content-Length: %s\r\n\r\nx", length)
			}
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, r)
			if err != nil {
				t.Fatalf("refusal waited for unfinished upload: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.want {
				t.Fatalf("status=%d, want %d", response.StatusCode, tc.want)
			}
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Fatalf("refusal body unavailable: %v", err)
			}
			if _, err := reader.ReadByte(); err != io.EOF {
				t.Fatalf("rejected connection stayed open: %v", err)
			}
			if reached.Load() != 0 || len(m.Snapshot().Requests) != 0 {
				t.Fatal("refused upload reached backend or became inference activity")
			}
		})
	}
}
