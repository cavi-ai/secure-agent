package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func TestLocalServicesCommandPreservesExplicitTargetsAndUncertainty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/local-services" || strings.Join(r.URL.Query()["endpoint"], ",") != "http://127.0.0.1:9000,http://[::1]:9001" {
			t.Errorf("incorrect assessment request: %s %s", r.Method, r.URL)
		}
		json.NewEncoder(w).Encode(localservice.Report{Scope: "selected endpoints only", Enforcement: "not_assessed", Managed: &localservice.ManagedRuntime{State: "unloaded", Transport: "inherited-unix-v1", Enforcement: "private_transport"}, Services: []localservice.Assessment{{Endpoint: "http://127.0.0.1:9000", Metadata: localservice.Probe{State: "access_refused", Status: 401}, Enforcement: "not_assessed"}}})
	}))
	defer srv.Close()
	client := srv.Client()
	client.Transport = localServiceTestTransport{base: srv.URL, next: client.Transport}
	for _, asJSON := range []bool{false, true} {
		args := []string{"--endpoint", "http://127.0.0.1:9000", "--endpoint", "http://[::1]:9001"}
		if asJSON {
			args = append(args, "--json")
		}
		var out bytes.Buffer
		if err := runLocalServices(client, args, &out); err != nil {
			t.Fatal(err)
		}
		if asJSON {
			var report localservice.Report
			if json.Unmarshal(out.Bytes(), &report) != nil || report.Enforcement != "not_assessed" {
				t.Fatalf("invalid JSON output: %s", out.String())
			}
		} else if !strings.Contains(out.String(), "access_refused (HTTP 401)") || !strings.Contains(out.String(), "Enforcement: not assessed") || !strings.Contains(out.String(), "Managed advisor: unloaded; inherited-unix-v1; private_transport") {
			t.Fatalf("uncertainty missing: %s", out.String())
		}
	}
	if err := runLocalServices(client, []string{"--endpoint"}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing endpoint accepted")
	}
	if err := runLocalServices(client, []string{"--unexpected"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown argument accepted")
	}
}

type localServiceTestTransport struct {
	base string
	next http.RoundTripper
}

func (tr localServiceTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = "http"
	u.Host = strings.TrimPrefix(tr.base, "http://")
	clone.URL = &u
	return tr.next.RoundTrip(clone)
}
