package main

// Tests for the fleet-posture rollup: status envelopes, windowed counts,
// version tracking, guard verdicts, sort order, and liveness thresholds.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func statusBody(t *testing.T, nodeID, hostname, posture string) []byte {
	t.Helper()
	b, err := json.Marshal(Envelope{
		NodeID: nodeID, Kind: "status", TS: time.Now().UTC().Format(time.RFC3339Nano),
		Version: "v1.2.3",
		Payload: json.RawMessage(`{"hostname":"` + hostname + `","os":"darwin","arch":"arm64","agents":2,` +
			`"posture_state":"` + posture + `","posture_summary":"summary for ` + posture + `","needs_you":1,` +
			`"labels":{"env":"prod"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func post(t *testing.T, srv *httptest.Server, secret string, body []byte, nodeID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", srv.URL+"/hooks/secure-agent", bytes.NewReader(body))
	req.Header.Set("X-SecureAgent-Signature", sign(t, secret, body))
	req.Header.Set("X-SecureAgent-Node", nodeID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHookAcceptsStatusKind(t *testing.T) {
	_, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	resp := post(t, srv, "s3cret", statusBody(t, "n1", "builder-01", "all-clear"), "n1")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status envelope: status=%d, want 200", resp.StatusCode)
	}
}

func TestStatusEnvelopeUpdatesPostureAndIdentity(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	mustAppend(t, s, Envelope{NodeID: "n1", Kind: "status", Version: "v1.2.3",
		Payload: json.RawMessage(`{"hostname":"builder-01","agents":2,"posture_state":"critical","posture_summary":"Secret leaving","needs_you":2,"labels":{"env":"prod"}}`)})

	st := s.Rollup()[0]
	if !st.HasStatus || st.Hostname != "builder-01" || st.PostureState != "critical" || st.NeedsYou != 2 {
		t.Fatalf("rollup = %+v", st)
	}
	if st.Labels["env"] != "prod" || st.Agents != 2 {
		t.Fatalf("labels/agents missing: %+v", st)
	}
}

func mustAppend(t *testing.T, s *Store, env Envelope) {
	t.Helper()
	if err := s.Append(env); err != nil {
		t.Fatal(err)
	}
}

// A node upgrade must be visible in the rollup — the first version to report
// must not be frozen forever (the old sticky-version bug).
func TestVersionTracksNewestReport(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	mustAppend(t, s, Envelope{NodeID: "n1", Kind: "flag", Version: "v1.0.0", Payload: json.RawMessage(`{}`)})
	mustAppend(t, s, Envelope{NodeID: "n1", Kind: "status", Version: "v1.1.0", Payload: json.RawMessage(`{"hostname":"h"}`)})
	if got := s.Rollup()[0].Version; got != "v1.1.0" {
		t.Fatalf("version = %q, want v1.1.0", got)
	}
	// Replay is chronological, so a fresh store lands on the newest too.
	if got := NewStore(dir).Rollup()[0].Version; got != "v1.1.0" {
		t.Fatalf("replayed version = %q, want v1.1.0", got)
	}
}

func TestWindowedCountsAndSeverityHarvest(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	mustAppend(t, s, Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{"rule":"aws-key","severity":3}`)})
	mustAppend(t, s, Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{"rule":"keychain-access","severity":1}`)})
	mustAppend(t, s, Envelope{NodeID: "n1", Kind: "incident", Version: "v1", Payload: json.RawMessage(`{"summary":"x","risk":"CRITICAL"}`)})

	st := s.Rollup()[0]
	if st.Flags24h != 2 || st.CriticalFlags24h != 1 || st.Incidents24h != 1 {
		t.Fatalf("windowed counts = %+v", st)
	}
	if st.Flags != 2 || st.Incidents != 1 { // lifetime counters kept
		t.Fatalf("lifetime counts = %+v", st)
	}

	// An event older than the window must not count: apply one directly with
	// a stale receipt time.
	old := time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339Nano)
	s.mu.Lock()
	s.apply(Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{"severity":3}`)}, old)
	s.mu.Unlock()
	if got := s.Rollup()[0]; got.Flags24h != 2 || got.CriticalFlags24h != 1 {
		t.Fatalf("stale event leaked into window: %+v", got)
	}
}

func TestGuardVerdictBreakdown(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	for _, v := range []string{"allow", "allow", "deny"} {
		mustAppend(t, s, Envelope{NodeID: "n1", Kind: "guard", Version: "v1",
			Payload: json.RawMessage(`{"verdict":"` + v + `"}`)})
	}
	st := s.Rollup()[0]
	if st.GuardDecisions != 3 || st.GuardAllows != 2 || st.GuardDenies != 1 {
		t.Fatalf("guard breakdown = %+v", st)
	}
	if st.LastEvent.IsZero() {
		t.Fatal("guard decisions are security activity — last_event must be set")
	}
}

// Cards sort by operator priority: critical posture first, then attention,
// then stale, then all-clear, then legacy event-only nodes.
func TestRollupSortsByOperatorPriority(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	status := func(id, state string) Envelope {
		return Envelope{NodeID: id, Kind: "status", Version: "v1",
			Payload: json.RawMessage(`{"hostname":"` + id + `","posture_state":"` + state + `"}`)}
	}
	mustAppend(t, s, status("z-clear", "all-clear"))
	mustAppend(t, s, Envelope{NodeID: "a-legacy", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{}`)})
	mustAppend(t, s, status("m-critical", "critical"))
	mustAppend(t, s, status("b-attention", "attention"))

	got := s.Rollup()
	want := []string{"m-critical", "b-attention", "z-clear", "a-legacy"}
	if len(got) != len(want) {
		t.Fatalf("rollup len = %d", len(got))
	}
	for i, id := range want {
		if got[i].NodeID != id {
			t.Fatalf("order[%d] = %s, want %s (full: %v)", i, got[i].NodeID, id, got)
		}
	}
}

func TestLivenessThresholds(t *testing.T) {
	now := time.Now()
	mk := func(hasStatus bool, age time.Duration) *NodeState {
		return &NodeState{NodeID: "n", HasStatus: hasStatus, LastSeen: now.Add(-age)}
	}
	cases := []struct {
		name string
		st   *NodeState
		want string
	}{
		{"heartbeat node fresh", mk(true, time.Minute), ""},
		{"heartbeat node stale at 4m", mk(true, 4*time.Minute), "stale"},
		{"heartbeat node gone at 11m", mk(true, 11*time.Minute), "gone"},
		{"legacy node fine at 4m", mk(false, 4*time.Minute), ""},
		{"legacy node stale at 11m", mk(false, 11*time.Minute), "stale"},
		{"legacy node gone at 21m", mk(false, 21*time.Minute), "gone"},
	}
	for _, c := range cases {
		if got := livenessState(c.st, now); got != c.want {
			t.Fatalf("%s: liveness = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestOverviewRendersHostnamePostureAndHeadline(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	_ = c
	resp := post(t, srv, "s3cret", statusBody(t, "n1", "builder-01", "all-clear"), "n1")
	resp.Body.Close()

	page := get(t, srv.URL+"/")
	if !strings.Contains(page, "builder-01") {
		t.Fatal("overview must title the card with the hostname")
	}
	if !strings.Contains(page, "ALL CLEAR") || !strings.Contains(page, "1 all-clear") {
		t.Fatal("overview missing posture chip or fleet headline")
	}
	if !strings.Contains(page, "env=prod") {
		t.Fatal("overview missing label chips")
	}
}

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.String()
}
