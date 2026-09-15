package main

// Tests for sequence-gap detection (2A) and cross-node rule aggregation (2B).

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// applyAt injects an envelope with a chosen receipt time (gapGrace makes
// wall-clock sleeps unnecessary).
func applyAt(s *Store, env Envelope, receivedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apply(env, receivedAt.Format(time.RFC3339Nano))
}

func seqEnv(nodeID, boot string, seq uint64) Envelope {
	return Envelope{NodeID: nodeID, Kind: "flag", Version: "v1", Boot: boot, Seq: seq,
		Payload: json.RawMessage(`{"rule":"aws-key","severity":3}`)}
}

func TestGapDetectionCountsMissingSeqs(t *testing.T) {
	s := NewStore(t.TempDir())
	old := time.Now().Add(-10 * time.Minute) // beyond gapGrace
	applyAt(s, seqEnv("n1", "bootA", 1), old)
	applyAt(s, seqEnv("n1", "bootA", 2), old)
	applyAt(s, seqEnv("n1", "bootA", 4), old) // seq 3 never arrived

	if got := s.Rollup()[0].Gaps; got != 1 {
		t.Fatalf("gaps = %d, want 1 (seq 3 lost)", got)
	}

	// Late arrival closes the hole — retries complete out of order.
	applyAt(s, seqEnv("n1", "bootA", 3), old)
	if got := s.Rollup()[0].Gaps; got != 0 {
		t.Fatalf("gaps = %d after late arrival, want 0", got)
	}
}

func TestGapDetectionBootResetIsNotLoss(t *testing.T) {
	s := NewStore(t.TempDir())
	old := time.Now().Add(-10 * time.Minute)
	applyAt(s, seqEnv("n1", "bootA", 5), old)
	// Daemon restarted: new boot starts at seq 1. The reset itself is not a
	// gap — first contact with a boot is the sync point.
	applyAt(s, seqEnv("n1", "bootB", 1), old)
	applyAt(s, seqEnv("n1", "bootB", 3), old) // seq 2 of bootB lost

	st := s.Rollup()[0]
	if st.BootID != "bootB" {
		t.Fatalf("boot = %q, want bootB", st.BootID)
	}
	if st.Gaps != 1 {
		t.Fatalf("gaps = %d, want 1 (only bootB's seq 2)", st.Gaps)
	}
}

func TestGapDetectionIgnoresLegacyEnvelopes(t *testing.T) {
	s := NewStore(t.TempDir())
	old := time.Now().Add(-10 * time.Minute)
	applyAt(s, Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{}`)}, old)
	applyAt(s, Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{}`)}, old)
	if got := s.Rollup()[0].Gaps; got != 0 {
		t.Fatalf("legacy node gaps = %d, want 0 (no boot/seq = no gap tracking)", got)
	}
}

// A hole younger than gapGrace is a retry in flight, not a confirmed loss.
func TestGapGracePeriod(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Now()
	applyAt(s, seqEnv("n1", "bootA", 1), now)
	applyAt(s, seqEnv("n1", "bootA", 3), now) // seq 2 missing but recent
	if got := s.Rollup()[0].Gaps; got != 0 {
		t.Fatalf("gaps = %d within grace, want 0", got)
	}
}

func TestRuleAggregatesCrossNode(t *testing.T) {
	s := NewStore(t.TempDir())
	mk := func(node, rule string, sev int) Envelope {
		p, _ := json.Marshal(map[string]any{"rule": rule, "severity": sev})
		return Envelope{NodeID: node, Kind: "flag", Version: "v1", Payload: p}
	}
	for _, env := range []Envelope{
		mk("n1", "sensitive-read-then-connect", 3),
		mk("n2", "sensitive-read-then-connect", 3),
		mk("n2", "sensitive-read-then-connect", 3),
		mk("n1", "keychain-access", 1),
	} {
		if err := s.Append(env); err != nil {
			t.Fatal(err)
		}
	}

	fr := s.RuleAggregates()
	if fr.TotalNodes != 2 {
		t.Fatalf("total_nodes = %d, want 2", fr.TotalNodes)
	}
	if len(fr.Rules) != 2 {
		t.Fatalf("rules = %v", fr.Rules)
	}
	top := fr.Rules[0]
	if top.Rule != "sensitive-read-then-connect" || top.Nodes != 2 || top.Flags24h != 3 || top.Critical24h != 3 {
		t.Fatalf("top aggregate = %+v", top)
	}
	if fr.Rules[1].Rule != "keychain-access" || fr.Rules[1].Nodes != 1 {
		t.Fatalf("second aggregate = %+v", fr.Rules[1])
	}
	// Spread beats volume: n2 fires the shared rule twice but that rule
	// already wins on node count; keychain (1 flag, 1 node) is second.
}

func TestFleetRulesEndpoint(t *testing.T) {
	_, srv := testCollector(t, map[string]string{"n1": "s3cret", "n2": "s3cret2"})
	for node, secret := range map[string]string{"n1": "s3cret", "n2": "s3cret2"} {
		body, _ := json.Marshal(Envelope{NodeID: node, Kind: "flag", Version: "v1",
			TS:      time.Now().UTC().Format(time.RFC3339Nano),
			Payload: json.RawMessage(`{"rule":"aws-key","severity":3}`)})
		resp := post(t, srv, secret, body, node)
		resp.Body.Close()
	}
	page := get(t, srv.URL+"/fleet/rules")
	if !strings.Contains(page, `"aws-key"`) || !strings.Contains(page, `"nodes":2`) {
		t.Fatalf("/fleet/rules = %s", page)
	}
	// And the overview carries the same aggregation.
	page = get(t, srv.URL+"/")
	if !strings.Contains(page, "Rules across the fleet") || !strings.Contains(page, "2/2 nodes") {
		t.Fatal("overview missing rules section")
	}
}

func TestOverviewShowsGaps(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	old := time.Now().Add(-10 * time.Minute)
	applyAt(c.store, seqEnv("n1", "bootA", 1), old)
	applyAt(c.store, seqEnv("n1", "bootA", 3), old)

	page := get(t, srv.URL+"/")
	if !strings.Contains(page, "1 deliverie(s) lost") {
		t.Fatal("overview missing gap warning")
	}
	if !bytes.Contains([]byte(page), []byte("aws-key")) {
		t.Fatal("overview missing rule aggregation for the node's flags")
	}
}
