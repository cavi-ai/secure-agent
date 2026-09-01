package guard

import (
	"testing"
	"time"
)

func TestResolveWakesRequest(t *testing.T) {
	b := NewBroker(2 * time.Second)
	done := make(chan Decision, 1)
	go func() { done <- b.Request(Pending{ID: "p1", Agent: "claude", RuleID: "cloud-creds"}) }()

	// Wait for it to register as pending, then resolve.
	deadline := time.After(time.Second)
	for {
		if len(b.Pending()) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("request never became pending")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !b.Resolve("p1", Decision{Verdict: "allow", Scope: "always"}) {
		t.Fatal("resolve returned false")
	}
	got := <-done
	if got.Verdict != "allow" || got.Scope != "always" {
		t.Fatalf("decision = %+v", got)
	}
	if len(b.Pending()) != 0 {
		t.Fatal("pending not cleared after resolve")
	}
}

func TestRequestTimesOutToDeny(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	got := b.Request(Pending{ID: "p2", Agent: "claude", RuleID: "ssh-keys"})
	if got.Verdict != "deny" || got.Scope != "once" || got.Reason != "timeout" {
		t.Fatalf("timeout decision = %+v, want deny/once/timeout", got)
	}
	if len(b.Pending()) != 0 {
		t.Fatal("timed-out request left dangling in pending")
	}
}

// TestConcurrentRequestsWithDistinctIDsResolveIndependently guards against the
// broker's map-key collision bug: two Request calls with distinct IDs (as the
// API must always generate, e.g. two agents or one agent's parallel tool
// calls prompting at the same time) must both surface in Pending() and each
// must resolve to its own decision, not the other's.
func TestConcurrentRequestsWithDistinctIDsResolveIndependently(t *testing.T) {
	b := NewBroker(2 * time.Second)
	done1 := make(chan Decision, 1)
	done2 := make(chan Decision, 1)
	go func() { done1 <- b.Request(Pending{ID: "c1", Agent: "claude", RuleID: "cloud-creds"}) }()
	go func() { done2 <- b.Request(Pending{ID: "c2", Agent: "cursor", RuleID: "ssh-keys"}) }()

	deadline := time.After(time.Second)
	for {
		if len(b.Pending()) == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("both requests never became pending, got %d", len(b.Pending()))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	if !b.Resolve("c1", Decision{Verdict: "allow", Scope: "once"}) {
		t.Fatal("resolve c1 returned false")
	}
	if !b.Resolve("c2", Decision{Verdict: "deny", Scope: "always"}) {
		t.Fatal("resolve c2 returned false")
	}

	got1 := <-done1
	got2 := <-done2
	if got1.Verdict != "allow" || got1.Scope != "once" {
		t.Fatalf("c1 decision = %+v, want allow/once", got1)
	}
	if got2.Verdict != "deny" || got2.Scope != "always" {
		t.Fatalf("c2 decision = %+v, want deny/always", got2)
	}
	if len(b.Pending()) != 0 {
		t.Fatal("pending not cleared after both resolved")
	}
}
