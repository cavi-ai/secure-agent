package main

import (
	"strings"
	"testing"
)

func TestFormatDoctor(t *testing.T) {
	rep := doctorReport{
		Summary: doctorSummary{Pass: 1, Fail: 1, Skip: 1},
		Checks: []doctorCheck{
			{ID: "hook-registered", Title: "Guard hook registered", State: "pass", Detail: "registered for PreToolUse and PostToolUse"},
			{ID: "file-telemetry", Title: "File telemetry", State: "fail", Detail: "root service state: spawn scheduled", Fix: "grant Full Disk Access"},
			{ID: "session-rate", Title: "Session creation rate", State: "skip", Detail: "no agents running"},
		},
	}
	out, code := formatDoctor(rep)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 with a failing check", code)
	}
	want := []string{
		"PASS  Guard hook registered — registered for PreToolUse and PostToolUse",
		"FAIL  File telemetry — root service state: spawn scheduled",
		"      fix: grant Full Disk Access",
		"SKIP  Session creation rate — no agents running",
		"1 pass · 1 fail · 1 skip",
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("output:\n%s\nwant:\n%s", out, strings.Join(want, "\n"))
	}
	if n := strings.Count(out, "fix:"); n != 1 {
		t.Fatalf("fix lines = %d, want 1 (only under the failure)", n)
	}
}

func TestFormatDoctorAllPassExitsZero(t *testing.T) {
	rep := doctorReport{
		Summary: doctorSummary{Pass: 2},
		Checks: []doctorCheck{
			{ID: "bus", Title: "Event bus", State: "pass", Detail: "no dropped events"},
			{ID: "retention", Title: "Event retention", State: "pass"},
		},
	}
	out, code := formatDoctor(rep)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 when nothing failed", code)
	}
	if !strings.Contains(out, "PASS  Event retention\n") || strings.Contains(out, "fix:") || !strings.HasSuffix(out, "2 pass · 0 fail · 0 skip\n") {
		t.Fatalf("output:\n%s", out)
	}
}
