package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type inferenceTransport func(*http.Request) (*http.Response, error)

func (f inferenceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLocalInferenceCLI(t *testing.T) {
	client := &http.Client{Transport: inferenceTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/local-inference" || r.Method != "GET" {
			t.Fatalf("request: %s %s", r.Method, r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"coverage":{"discovery":"available","connections":"partial","requests":"routed_only"},"servers":[],"connections":[],"requests":[],"gateways":[]}`))}, nil
	})}
	var out bytes.Buffer
	if err := runLocalInference(client, []string{"--json"}, &out); err != nil || !strings.Contains(out.String(), `"routed_only"`) {
		t.Fatalf("JSON: %s %v", out.String(), err)
	}
	out.Reset()
	if err := runLocalInference(client, nil, &out); err != nil || !strings.Contains(out.String(), "partial") {
		t.Fatalf("text: %s %v", out.String(), err)
	}
	if err := runLocalInference(client, []string{"--prompt", "anything"}, &out); err == nil {
		t.Fatal("unexpected option accepted")
	}
}
