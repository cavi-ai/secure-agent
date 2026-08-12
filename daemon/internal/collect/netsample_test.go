package collect

import (
	"testing"
)

func TestDiffConnections(t *testing.T) {
	k1 := connKey{PID: 200, Host: "a.com", Port: 443}
	k2 := connKey{PID: 200, Host: "b.com", Port: 80}

	prev := map[connKey]struct{}{k1: {}}
	cur := map[connKey]struct{}{k1: {}, k2: {}}

	opened, closed := DiffConnections(prev, cur)
	if len(opened) != 1 || opened[0] != k2 {
		t.Fatalf("opened = %+v, want [%+v]", opened, k2)
	}
	if len(closed) != 0 {
		t.Fatalf("closed = %+v, want empty", closed)
	}

	// Disappearance
	cur2 := map[connKey]struct{}{}
	opened2, closed2 := DiffConnections(cur, cur2)
	if len(opened2) != 0 {
		t.Fatalf("opened2 = %+v, want empty", opened2)
	}
	if len(closed2) != 2 {
		t.Fatalf("closed2 = %+v, want 2 items", closed2)
	}
}
