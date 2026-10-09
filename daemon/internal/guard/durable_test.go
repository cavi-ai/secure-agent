package guard

import (
	"context"
	"errors"
	"testing"
	"time"
)

func awaitPending(t *testing.T, b *Broker) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(b.Pending()) == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request did not register")
}

func TestDurableResolveDeadlineDoesNotCommit(t *testing.T) {
	b := NewBroker(60 * time.Millisecond)
	answer := make(chan Decision, 1)
	go func() { answer <- b.Request(context.Background(), Pending{ID: "p"}) }()
	awaitPending(t, b)
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan bool, 1)
	committed, rolledBack := false, false
	go func() {
		ok, _ := b.ResolveWith("p", Decision{Verdict: "allow", Scope: "session"}, func(ctx context.Context, p Pending) (func() error, func(), error) {
			close(entered)
			<-release
			return func() error { committed = true; return nil }, func() { rolledBack = true }, nil
		})
		finished <- ok
	}()
	<-entered
	select {
	case d := <-answer:
		if d.Verdict != "deny" || d.Reason != "timeout" {
			t.Fatalf("deadline answer: %+v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("database preparation blocked fail-safe deadline")
	}
	close(release)
	if <-finished || committed || !rolledBack {
		t.Fatal("expired preparation activated permission")
	}
}

func TestDurableResolveFailureKeepsPendingAndCannotDoubleCommit(t *testing.T) {
	b := NewBroker(time.Second)
	answer := make(chan Decision, 1)
	go func() { answer <- b.Request(context.Background(), Pending{ID: "p"}) }()
	awaitPending(t, b)
	boom := errors.New("save failed")
	ok, err := b.ResolveWith("p", Decision{Verdict: "allow", Scope: "session"}, func(context.Context, Pending) (func() error, func(), error) {
		return func() error { return boom }, func() {}, nil
	})
	if ok || !errors.Is(err, boom) || len(b.Pending()) != 1 {
		t.Fatalf("failed save removed prompt: %v %v", ok, err)
	}
	commits := 0
	prepare := func(context.Context, Pending) (func() error, func(), error) {
		return func() error { commits++; return nil }, func() {}, nil
	}
	if ok, err = b.ResolveWith("p", Decision{Verdict: "allow", Scope: "session"}, prepare); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ = b.ResolveWith("p", Decision{Verdict: "allow", Scope: "session"}, prepare); ok || commits != 1 {
		t.Fatal("decision committed twice")
	}
	if d := <-answer; d.Verdict != "allow" {
		t.Fatal(d)
	}
}
