package guard

import (
	"fmt"
	"sync"
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

// A request identical to one already in flight must block on the same waiter:
// one resolution answers both, and only one prompt is queued.
func TestDuplicateRequestsShareOneWaiter(t *testing.T) {
	b := NewBroker(2 * time.Second)
	d1 := make(chan Decision, 1)
	d2 := make(chan Decision, 1)
	p := Pending{ID: "a1", Agent: "claude", Tool: "Read", Path: "/Users/x/.aws/credentials", RuleID: "cloud-creds"}
	go func() { d1 <- b.Request(p) }()
	// Wait until the first is queued so the second is guaranteed a duplicate.
	for len(b.Pending()) == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	dup := p
	dup.ID = "a2"
	go func() { d2 <- b.Request(dup) }()
	time.Sleep(30 * time.Millisecond)
	if got := len(b.Pending()); got != 1 {
		t.Fatalf("pending = %d, want 1 (duplicates share a waiter)", got)
	}
	if !b.Resolve("a1", Decision{Verdict: "allow", Scope: "always"}) {
		t.Fatal("resolve a1 returned false")
	}
	got1, got2 := <-d1, <-d2
	if got1.Verdict != "allow" || got2.Verdict != "allow" {
		t.Fatalf("duplicate got %+v / %+v, want both allow", got1, got2)
	}
}

// Once the queue is full, further requests get an immediate explicit deny
// instead of piling up.
func TestRequestOverCapIsDeniedImmediately(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	var wg sync.WaitGroup
	queued := make(chan struct{}, MaxWaiters)
	for i := 0; i < MaxWaiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b.Request(Pending{ID: fmt.Sprintf("w%d", i), Agent: "claude", RuleID: "r", Path: fmt.Sprintf("/p%d", i), Tool: "Read"})
			queued <- struct{}{}
		}(i)
	}
	// Wait for the queue to fill.
	deadline := time.After(2 * time.Second)
	for len(b.Pending()) < MaxWaiters {
		select {
		case <-deadline:
			t.Fatalf("queue never filled: %d", len(b.Pending()))
		default:
			time.Sleep(2 * time.Millisecond)
		}
	}
	// This one must be refused instantly, not block for the broker timeout.
	start := time.Now()
	d := b.Request(Pending{ID: "overflow", Agent: "claude", RuleID: "r", Path: "/overflow", Tool: "Read"})
	if d.Verdict != "deny" || d.Reason != "queue-full" {
		t.Fatalf("overflow decision = %+v, want deny/queue-full", d)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("overflow took %v, want an immediate refusal", elapsed)
	}
	// Drain: resolve everything so the goroutines exit.
	time.Sleep(20 * time.Millisecond)
	b.mu.Lock()
	ids := make([]string, 0, len(b.waiters))
	for id := range b.waiters {
		ids = append(ids, id)
	}
	b.mu.Unlock()
	for _, id := range ids {
		b.Resolve(id, Decision{Verdict: "deny", Scope: "once"})
	}
	wg.Wait()
}

// Resolve iterates w.chs while concurrent duplicate Requests append to it.
// Run under `go test -race`: before the fix (lock dropped before iterating),
// this is a reliable data race on the slice header/backing array.
//
// The test must not depend on goroutine scheduling order: duplicates that
// register AFTER the primary's waiter is resolved get their own waiter (a
// second prompt — correct behavior), so we deterministically wait until half
// the duplicates have joined before resolving, and resolve the rest's fresh
// waiters in the drain phase.
func TestResolveConcurrentWithDuplicateRequests(t *testing.T) {
	// Short broker timeout: any duplicate that ends up with its own waiter
	// after the drain window fails fast instead of stalling the suite.
	b := NewBroker(400 * time.Millisecond)
	p := Pending{ID: "r1", Agent: "claude", Tool: "Read", Path: "/Users/x/.aws/credentials", RuleID: "cloud-creds"}
	done := make(chan Decision, 1)
	go func() { done <- b.Request(p) }()
	for len(b.Pending()) == 0 {
		time.Sleep(time.Millisecond)
	}

	const dups = 64
	const joined = dups / 2 // these MUST share r1's waiter
	var wg sync.WaitGroup
	results := make(chan Decision, dups)
	for i := 0; i < dups; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dup := p
			dup.ID = fmt.Sprintf("r1-dup%d", i)
			results <- b.Request(dup)
		}(i)
	}

	// Wait until `joined` duplicates have actually registered on r1's waiter
	// (same-package access; this is what the race detector needs to see —
	// appends concurrent with Resolve's iteration).
	waitJoined := func(want int) {
		deadline := time.After(5 * time.Second)
		for {
			b.mu.Lock()
			n := 0
			if w, ok := b.waiters["r1"]; ok {
				n = len(w.chs)
			}
			b.mu.Unlock()
			if n >= want {
				return
			}
			select {
			case <-deadline:
				t.Fatalf("only %d channels joined r1's waiter, want %d", n, want)
			default:
				time.Sleep(time.Millisecond)
			}
		}
	}
	waitJoined(joined + 1) // +1 for the primary's own channel

	// Resolve concurrently with the remaining appends — the race window. Note:
	// once the primary's channel receives a decision, Request returns and the
	// waiter is deleted; late duplicates then create their own waiters (a
	// second prompt — correct). We don't require all 64 to share the waiter,
	// only that appends overlap resolves.
	stopResolving := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopResolving:
				return
			default:
				b.Resolve("r1", Decision{Verdict: "allow", Scope: "once"})
				time.Sleep(time.Millisecond)
			}
		}
	}()
	time.Sleep(150 * time.Millisecond)
	close(stopResolving)
	// One final fan-out in case the waiter survived the window.
	b.Resolve("r1", Decision{Verdict: "allow", Scope: "once"})

	// Drain: late duplicates that created their own waiters get resolved too.
	deadline := time.After(5 * time.Second)
	for {
		b.mu.Lock()
		ids := make([]string, 0, len(b.waiters))
		for id := range b.waiters {
			ids = append(ids, id)
		}
		b.mu.Unlock()
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			b.Resolve(id, Decision{Verdict: "allow", Scope: "once"})
		}
		select {
		case <-deadline:
			t.Fatalf("waiters never drained: %v", ids)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	wg.Wait()
	close(results)
	allowed := 0
	for d := range results {
		if d.Verdict == "allow" {
			allowed++
		}
	}
	if allowed < joined {
		t.Fatalf("only %d/%d duplicates got the fanned-out decision, want at least %d", allowed, dups, joined)
	}
	<-done
}

// Pending must come back oldest-first so the menubar prompts the
// longest-waiting request first. Distinct paths so the dedup key does not
// collapse them into one waiter.
func TestPendingReturnsOldestFirst(t *testing.T) {
	b := NewBroker(2 * time.Second)
	done := make(chan Decision, 3)
	ids := []string{"first", "second", "third"}
	for i, id := range ids {
		path := fmt.Sprintf("/p%d", i)
		go func(id, path string) {
			done <- b.Request(Pending{ID: id, Agent: "a", RuleID: "r", Path: path, Tool: "Read"})
		}(id, path)
		time.Sleep(10 * time.Millisecond) // enforce arrival order
	}
	p := b.Pending()
	if len(p) != 3 || p[0].ID != "first" || p[2].ID != "third" {
		t.Fatalf("pending order = %v, want first,second,third", p)
	}
	for _, id := range ids {
		b.Resolve(id, Decision{Verdict: "allow", Scope: "once"})
	}
}
