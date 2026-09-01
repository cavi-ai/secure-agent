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
