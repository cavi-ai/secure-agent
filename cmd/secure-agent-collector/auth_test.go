package main

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorRejectsUnauthenticatedNetworkBind(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_COLLECTOR_STARTUP") == "1" {
		flag.CommandLine = flag.NewFlagSet("secure-agent-collector", flag.ExitOnError)
		os.Args = []string{"secure-agent-collector", "-addr", "192.0.2.1:9445", "-read-token", "", "-secrets", "test-node=test-signing-key", "-store", os.Getenv("SECURE_AGENT_TEST_COLLECTOR_STORE")}
		main()
		return
	}
	store := filepath.Join(t.TempDir(), "store")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCollectorRejectsUnauthenticatedNetworkBind$")
	command.Env = append(os.Environ(), "SECURE_AGENT_TEST_COLLECTOR_STARTUP=1", "SECURE_AGENT_TEST_COLLECTOR_STORE="+store)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("collector did not refuse startup promptly")
	}
	if err == nil || !strings.Contains(string(output), "-read-token is required for a non-loopback listen address") {
		t.Fatalf("collector must reject configuration before binding: err=%v, output=%s", err, output)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected configuration created a store: %v", err)
	}
}

func TestCollectorReadAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name    string
		addr    string
		token   string
		headers []string
		want    int
	}{
		{"local IPv4", "127.0.0.1:9445", "", nil, 200},
		{"local IPv6", "[::1]:9445", "", nil, 200},
		{"localhost", "localhost:9445", "", nil, 200},
		{"wildcard IPv4", "0.0.0.0:9445", "", nil, 401},
		{"wildcard IPv6", "[::]:9445", "", nil, 401},
		{"empty host", ":9445", "", nil, 401},
		{"network address", "192.0.2.1:9445", "", nil, 401},
		{"unknown hostname", "collector.example:9445", "", nil, 401},
		{"missing token", "127.0.0.1:9445", "test-read-key", nil, 401},
		{"wrong token", "192.0.2.1:9445", "test-read-key", []string{"Bearer wrong-test-key"}, 401},
		{"missing bearer scheme", "192.0.2.1:9445", "test-read-key", []string{"test-read-key"}, 401},
		{"duplicate authorization", "192.0.2.1:9445", "test-read-key", []string{"Bearer test-read-key", "Bearer wrong-test-key"}, 401},
		{"authenticated loopback", "127.0.0.1:9445", "test-read-key", []string{"Bearer test-read-key"}, 200},
		{"authenticated network", "192.0.2.1:9445", "test-read-key", []string{"Bearer test-read-key"}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Collector{cfg: Config{Addr: tc.addr, ReadToken: tc.token}, store: NewStore(t.TempDir())}
			r := httptest.NewRequest(http.MethodGet, "/fleet", nil)
			for _, header := range tc.headers {
				r.Header.Add("Authorization", header)
			}
			w := httptest.NewRecorder()
			c.requireReadAuth(c.handleFleet)(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d, want %d", w.Code, tc.want)
			}
		})
	}
}
