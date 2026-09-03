package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCollector(t *testing.T, secrets map[string]string) (*Collector, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	c := &Collector{
		cfg:   Config{Secrets: secrets, StoreDir: dir},
		store: NewStore(dir),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hooks/secure-agent", c.handleHook)
	mux.HandleFunc("GET /fleet", c.handleFleet)
	mux.HandleFunc("GET /nodes/", c.handleNodeEvents)
	mux.HandleFunc("GET /", c.handleOverview)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return c, srv
}

func sign(t *testing.T, secret string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func envelope(nodeID, kind string) []byte {
	b, _ := json.Marshal(Envelope{
		NodeID: nodeID, Kind: kind, TS: time.Now().UTC().Format(time.RFC3339Nano),
		Version: "v0.9.0-rc.1",
		Payload: json.RawMessage(`{"rule":"aws-key","summary":"Secret leaving in agent traffic"}`),
	})
	return b
}

func TestHookAcceptsSignedEnvelope(t *testing.T) {
	_, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	body := envelope("n1", "flag")
	req, _ := http.NewRequest("POST", srv.URL+"/hooks/secure-agent", bytes.NewReader(body))
	req.Header.Set("X-SecureAgent-Signature", sign(t, "s3cret", body))
	req.Header.Set("X-SecureAgent-Node", "n1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("signed post: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHookRejectsBadSignature(t *testing.T) {
	_, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	cases := map[string]func(*http.Request){
		"missing header": func(r *http.Request) { r.Header.Del("X-SecureAgent-Signature") },
		"wrong prefix":   func(r *http.Request) { r.Header.Set("X-SecureAgent-Signature", "md5=abc") },
		"wrong secret": func(r *http.Request) {
			r.Header.Set("X-SecureAgent-Signature", sign(t, "other-secret", envelope("n1", "flag")))
		},
		"unknown node": func(r *http.Request) { r.Header.Set("X-SecureAgent-Node", "ghost") },
	}
	for name, mutate := range cases {
		body := envelope("n1", "flag")
		req, _ := http.NewRequest("POST", srv.URL+"/hooks/secure-agent", bytes.NewReader(body))
		req.Header.Set("X-SecureAgent-Signature", sign(t, "s3cret", body))
		req.Header.Set("X-SecureAgent-Node", "n1")
		mutate(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status=%d, want 401", name, resp.StatusCode)
		}
	}
	// Tampered body: valid signature over the original bytes, different bytes sent.
	body := envelope("n1", "flag")
	goodSig := sign(t, "s3cret", body)
	req, _ := http.NewRequest("POST", srv.URL+"/hooks/secure-agent", bytes.NewReader(envelope("n1", "guard")))
	req.Header.Set("X-SecureAgent-Signature", goodSig)
	req.Header.Set("X-SecureAgent-Node", "n1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered body: status=%d, want 401", resp.StatusCode)
	}
}

func TestHookRejectsNodeMismatch(t *testing.T) {
	_, srv := testCollector(t, map[string]string{"n1": "s3cret", "n2": "s3cret2"})
	// Validly signed with n1's secret, but the envelope body claims to be n2:
	// a compromised n1 must not be able to poison n2's rollup.
	body, _ := json.Marshal(Envelope{NodeID: "n2", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{}`)})
	req, _ := http.NewRequest("POST", srv.URL+"/hooks/secure-agent", bytes.NewReader(body))
	req.Header.Set("X-SecureAgent-Signature", sign(t, "s3cret", body)) // n1's secret (header node)
	req.Header.Set("X-SecureAgent-Node", "n1")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("node mismatch: status=%d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestStorePersistsAndReplays(t *testing.T) {
	dir := t.TempDir()
	s1 := NewStore(dir)
	if err := s1.Append(Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{"rule":"aws-key"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Append(Envelope{NodeID: "n1", Kind: "incident", Version: "v1", Payload: json.RawMessage(`{"summary":"Secret leaving in agent traffic"}`)}); err != nil {
		t.Fatal(err)
	}

	// Rollup reflects both.
	rollup := s1.Rollup()
	if rollupLen(rollup) != 1 || rollup[0].Flags != 1 || rollup[0].Incidents != 1 {
		t.Fatalf("rollup = %+v", rollup)
	}
	if rollup[0].LatestIncident != "Secret leaving in agent traffic" {
		t.Fatalf("latest incident = %q", rollup[0].LatestIncident)
	}

	// Store file is user-private.
	fi, _ := os.Stat(filepath.Join(dir, "n1.jsonl"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("store perms = %v", fi.Mode().Perm())
	}

	// A fresh store replays the log into the same rollup.
	s2 := NewStore(dir)
	r2 := s2.Rollup()
	if len(r2) != 1 || r2[0].Flags != 1 || r2[0].Incidents != 1 {
		t.Fatalf("replayed rollup = %+v", r2)
	}
}

// rollupLen is a tiny helper to keep the test above readable.
func rollupLen(states []*NodeState) int { return len(states) }

func TestQueryFiltersByKindNewestFirst(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	for _, k := range []string{"flag", "guard", "flag", "incident"} {
		if err := s.Append(Envelope{NodeID: "n1", Kind: k, Version: "v1", Payload: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	got := s.Query("n1", map[string]bool{"flag": true}, 10)
	if len(got) != 2 {
		t.Fatalf("flag query = %d, want 2", len(got))
	}
	for _, rec := range got {
		if rec.Envelope.Kind != "flag" {
			t.Fatalf("kind filter leaked: %+v", rec.Envelope)
		}
	}
	all := s.Query("n1", nil, 10)
	if all[0].Envelope.Kind != "incident" { // newest first
		t.Fatalf("order = %+v, want incident first", all[0].Envelope)
	}
}

func TestSanitizeBlocksPathTraversal(t *testing.T) {
	if got := sanitize("../../etc/passwd"); strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Fatalf("sanitize leaked path separators: %q", got)
	}
	if sanitize("") != "unknown-node" {
		t.Fatal("empty node id must map to unknown-node")
	}
}

func TestOverviewRendersNodesAndStaleness(t *testing.T) {
	_, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	// Deliver one event so the node exists.
	body := envelope("n1", "flag")
	req, _ := http.NewRequest("POST", srv.URL+"/hooks/secure-agent", bytes.NewReader(body))
	req.Header.Set("X-SecureAgent-Signature", sign(t, "s3cret", body))
	req.Header.Set("X-SecureAgent-Node", "n1")
	http.DefaultClient.Do(req)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	page := buf.String()
	if !strings.Contains(page, "n1") || !strings.Contains(page, "v0.9.0-rc.1") {
		t.Fatal("overview missing node card")
	}
	if strings.Contains(page, "gone quiet") {
		t.Fatal("fresh node flagged stale")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("overview missing nosniff")
	}
}

func TestFleetEndpointEmpty(t *testing.T) {
	_, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	resp, _ := http.Get(srv.URL + "/fleet")
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Fatalf("empty fleet = %q, want []", buf.String())
	}
}
