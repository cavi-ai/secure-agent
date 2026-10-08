package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDelayedRetiredBootPreservesActiveGap(t *testing.T) {
	rt := &nodeRuntime{state: &NodeState{}}
	old := time.Now().Add(-10 * time.Minute)
	rt.trackSeq("A", 10, old)
	rt.trackSeq("B", 1, old)
	rt.trackSeq("B", 3, old)
	rt.trackSeq("A", 11, old)
	if rt.state.BootID != "B" || rt.gapCount(time.Now()) != 1 {
		t.Fatalf("retired boot replaced current stream: boot=%s gaps=%d", rt.state.BootID, rt.gapCount(time.Now()))
	}
}

func TestRetiredBootKeepsEvidenceWithoutRollingBackVersion(t *testing.T) {
	s := &Store{nodes: make(map[string]*nodeRuntime)}
	at := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano)
	for _, env := range []Envelope{
		{NodeID: "n", Boot: "old", Seq: 1, Version: "old", Kind: "flag"},
		{NodeID: "n", Boot: "new", Seq: 1, Version: "new", Kind: "flag"},
		{NodeID: "n", Boot: "new", Seq: 3, Version: "new", Kind: "flag"},
		{NodeID: "n", Boot: "old", Seq: 2, Version: "old", Kind: "flag", Payload: json.RawMessage(`{"rule":"late-critical"}`)},
	} {
		s.apply(env, at)
	}
	rt := s.nodes["n"]
	if rt.state.Version != "new" || rt.state.BootID != "new" || rt.gapCount(time.Now()) != 1 || rt.state.Flags != 4 || rt.state.LatestFlag != "late-critical" {
		t.Fatalf("late delivery damaged state: %+v", rt.state)
	}
}

func TestLargeSequenceJumpCountsLossWithoutExpandingEveryHole(t *testing.T) {
	rt := &nodeRuntime{state: &NodeState{}}
	old := time.Now().Add(-10 * time.Minute)
	rt.trackSeq("A", 1, old)
	rt.trackSeq("A", 10001, old)
	if got := rt.gapCount(time.Now()); got != 9999 {
		t.Fatalf("gaps = %d", got)
	}
	rt.trackSeq("A", 2, old)
	if got := rt.gapCount(time.Now()); got != 9998 {
		t.Fatalf("late delivery did not close gap: %d", got)
	}
}
