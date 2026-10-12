// Package testutil provides assertions shared by package tests.
package testutil

import "testing"

// Read checks an error-returning read. The curried form accepts a method's
// complete result without discarding its error or adding temporary variables.
func Read[T any](t testing.TB) func(T, error) T {
	t.Helper()
	return func(value T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		return value
	}
}

// Lookup checks a read while preserving healthy absence as a result.
func Lookup[T any](t testing.TB) func(T, bool, error) (T, bool) {
	t.Helper()
	return func(value T, found bool, err error) (T, bool) {
		t.Helper()
		if err != nil {
			t.Fatalf("lookup failed: %v", err)
		}
		return value, found
	}
}

func Counts(t testing.TB) func(int, int, error) (int, int) {
	t.Helper()
	return func(first, second int, err error) (int, int) {
		t.Helper()
		if err != nil {
			t.Fatalf("counts failed: %v", err)
		}
		return first, second
	}
}
