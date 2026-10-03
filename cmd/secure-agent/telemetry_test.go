package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestTelemetryRepairOpensURLAndSucceedsOnceRunning(t *testing.T) {
	var opened []string
	states := []string{"spawn scheduled (last exit 78: EX_CONFIG)", "spawn scheduled (last exit 78: EX_CONFIG)", "running"}
	reads := 0
	readState := func() (string, error) {
		s := states[min(reads, len(states)-1)]
		reads++
		return s, nil
	}
	var out bytes.Buffer
	code := telemetryRepair(&out, func(u string) error { opened = append(opened, u); return nil }, readState,
		time.Second, time.Millisecond)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 once the state is running; output: %s", code, out.String())
	}
	if len(opened) != 1 || opened[0] != "secure-agent://telemetry/repair" {
		t.Fatalf("opened = %v, want [secure-agent://telemetry/repair]", opened)
	}
	if reads != 3 {
		t.Fatalf("reads = %d, want 3 (polls until running)", reads)
	}
	if !strings.Contains(out.String(), "file telemetry: running") {
		t.Fatalf("output: %s", out.String())
	}
}

func TestTelemetryRepairExitsOneWithLastStateOnTimeout(t *testing.T) {
	opened := 0
	readState := func() (string, error) { return "running (last exit 78: EX_CONFIG)", nil }
	var out bytes.Buffer
	code := telemetryRepair(&out, func(string) error { opened++; return nil }, readState,
		20*time.Millisecond, time.Millisecond)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 when the state never turns running", code)
	}
	if opened != 1 {
		t.Fatalf("opened %d times, want 1", opened)
	}
	if !strings.Contains(out.String(), "last state: running (last exit 78: EX_CONFIG)") {
		t.Fatalf("output does not name the last state: %s", out.String())
	}
}
