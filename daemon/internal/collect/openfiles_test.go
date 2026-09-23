package collect

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const rolloutA = "/Users/u/.codex/sessions/2026/09/23/rollout-2026-09-23T04-01-20-0199aabb-ccdd-7eef-8011-223344556677.jsonl"
const rolloutB = "/Volumes/x/codex-home/sessions/2026/09/23/rollout-2026-09-23T05-00-00-0199aabb-ccdd-7eef-8011-2233445566ff.jsonl"

func TestRolloutSessionID(t *testing.T) {
	cases := map[string]string{
		rolloutA: "0199aabb-ccdd-7eef-8011-223344556677",
		rolloutB: "0199aabb-ccdd-7eef-8011-2233445566ff",
		"/Users/u/.codex/sessions/2026/09/23/rollout-2026-09-23T04-01-20.jsonl":                    "",
		"/Users/u/.codex/sessions/2026/09/23/rollout-x-0199aabb-ccdd-7eef-8011-22334455667z.jsonl": "",
		"/Users/u/.codex/history.jsonl": "",
	}
	for path, want := range cases {
		if got := RolloutSessionID(path); got != want {
			t.Errorf("RolloutSessionID(%q) = %q, want %q", path, got, want)
		}
	}
}

// lsof -F output: a p line opens each process, f and n lines name its files.
// Only rollouts under a sessions directory are kept.
func TestParseLsofRolloutFiles(t *testing.T) {
	out := strings.Join([]string{
		"p100", "fcwd", "n/Users/u/.openclaw", "f3", "n/Users/u/.codex/history.jsonl",
		"f7", "n" + rolloutA,
		"p200", "f4", "n/dev/null",
		"p300", "f9", "n" + rolloutB, "f10", "n" + rolloutA,
		"",
	}, "\n")
	got := parseLsofRolloutFiles([]byte(out))
	want := map[int32][]string{100: {rolloutA}, 300: {rolloutB, rolloutA}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parse = %v, want %v", got, want)
	}
}

// One lsof call per 64 pids, comma-joined; a nonzero exit with output (a pid
// exited mid-scan) still yields the files lsof listed.
func TestLsofRolloutFilesBatchesPIDs(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) > 1 {
			return nil, nil
		}
		return []byte("p1\nf7\nn" + rolloutA + "\n"), errors.New("signal: killed")
	}
	pids := make([]int32, 130)
	for i := range pids {
		pids[i] = int32(i + 1)
	}
	got, err := lsofRolloutFiles(run, "/usr/sbin/lsof", pids)
	if err == nil {
		t.Fatal("runner error not reported")
	}
	if len(calls) != 3 {
		t.Fatalf("lsof calls = %d, want 3 for 130 pids", len(calls))
	}
	first := calls[0]
	if first[0] != "/usr/sbin/lsof" || !slices.Contains(first, "-Fn") {
		t.Fatalf("argv = %v, want /usr/sbin/lsof … -Fn", first)
	}
	i := slices.Index(first, "-p")
	if i < 0 || strings.Count(first[i+1], ",") != 63 || !strings.HasPrefix(first[i+1], "1,2,") {
		t.Fatalf("argv = %v, want -p with 64 comma-joined pids", first)
	}
	if !reflect.DeepEqual(got[1], []string{rolloutA}) {
		t.Fatalf("files = %v, want pid 1 → rolloutA", got)
	}
}

// The joiner probes only live codex pids and joins each open rollout's
// session to the pid holding it; a path with no session id is skipped.
func TestRolloutJoinerTick(t *testing.T) {
	var probed []int32
	type join struct {
		sid string
		pid int32
	}
	var joins []join
	j := &RolloutJoiner{
		PIDs: func() []int32 { return []int32{300, 100} },
		Probe: func(pids []int32) (map[int32][]string, error) {
			probed = append(probed, pids...)
			return map[int32][]string{100: {rolloutA}, 300: {rolloutB, "/x/sessions/rollout-bad.jsonl"}}, nil
		},
		SessionFor: func(path string) string { return RolloutSessionID(path) },
		Join:       func(sid string, pid int32) { joins = append(joins, join{sid, pid}) },
	}
	j.tick(time.Now())
	if !reflect.DeepEqual(probed, []int32{100, 300}) {
		t.Fatalf("probed = %v, want [100 300]", probed)
	}
	want := []join{{"0199aabb-ccdd-7eef-8011-223344556677", 100}, {"0199aabb-ccdd-7eef-8011-2233445566ff", 300}}
	if !reflect.DeepEqual(joins, want) {
		t.Fatalf("joins = %v, want %v", joins, want)
	}
}

// No live codex pid: no probe runs.
func TestRolloutJoinerSkipsProbeWithoutPIDs(t *testing.T) {
	j := &RolloutJoiner{
		PIDs:  func() []int32 { return nil },
		Probe: func([]int32) (map[int32][]string, error) { t.Fatal("probe ran with no pids"); return nil, nil },
	}
	j.tick(time.Now())
}

// The scanner names a rollout's session: the tracer's session_meta id once
// read, the file name's id before that.
func TestScannerRolloutSession(t *testing.T) {
	ts := NewTranscriptScanner(nil, nil)
	if got := ts.RolloutSession(rolloutA); got != "0199aabb-ccdd-7eef-8011-223344556677" {
		t.Fatalf("before session_meta = %q, want the file name id", got)
	}
	ts.noteRolloutSession(rolloutA, "meta-id")
	if got := ts.RolloutSession(rolloutA); got != "meta-id" {
		t.Fatalf("after session_meta = %q, want meta-id", got)
	}
}
