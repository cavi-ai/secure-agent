package connpeer

import (
	"context"
	"errors"
	"testing"
)

func TestPIDLooksUpOncePerConnection(t *testing.T) {
	calls := 0
	lookup := func(string) (int32, error) { calls++; return 42, nil }
	ctx := WithCache(context.Background(), nil)
	for i := 0; i < 3; i++ {
		if pid, err := PID(ctx, "127.0.0.1:50000", lookup); pid != 42 || err != nil {
			t.Fatalf("PID = %d, %v", pid, err)
		}
	}
	if calls != 1 {
		t.Fatalf("lookup ran %d times on one connection, want 1", calls)
	}
	if _, _ = PID(WithCache(context.Background(), nil), "127.0.0.1:50001", lookup); calls != 2 {
		t.Fatalf("a new connection reused another's pid (lookups %d)", calls)
	}
}

func TestPIDRetriesAFailedLookup(t *testing.T) {
	calls := 0
	lookup := func(string) (int32, error) {
		calls++
		if calls == 1 {
			return 0, errors.New("lsof timed out")
		}
		return 7, nil
	}
	ctx := WithCache(context.Background(), nil)
	if _, err := PID(ctx, "127.0.0.1:50000", lookup); err == nil {
		t.Fatal("first lookup error not returned")
	}
	if pid, err := PID(ctx, "127.0.0.1:50000", lookup); pid != 7 || err != nil {
		t.Fatalf("retry = %d, %v, want 7", pid, err)
	}
}

func TestPIDWithoutCacheLooksUpEveryTime(t *testing.T) {
	calls := 0
	lookup := func(string) (int32, error) { calls++; return 1, nil }
	for i := 0; i < 2; i++ {
		_, _ = PID(context.Background(), "127.0.0.1:50000", lookup)
	}
	if calls != 2 {
		t.Fatalf("lookups = %d, want 2", calls)
	}
}
