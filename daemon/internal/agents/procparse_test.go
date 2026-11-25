package agents

import (
	"fmt"
	"testing"
	"time"
)

func TestParseProcStatStartAndPPID(t *testing.T) {
	// Minimal /proc/pid/stat: pid (comm) state ppid ... starttime at field 22.
	// After ')': state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt
	// utime stime cutime cstime priority nice numthreads itrealvalue starttime ...
	stat := "12 (code) S 7 12 12 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 12345"
	boot := time.Unix(1_000_000, 0)
	ppid, comm, start, cpu := parseProcStat(stat, boot, 100)
	if ppid != 7 || comm != "code" {
		t.Fatalf("ppid=%d comm=%q", ppid, comm)
	}
	want := boot.Add(12345 * time.Second / 100)
	if !start.Equal(want) {
		t.Fatalf("start=%v want %v", start, want)
	}
	if cpu != 0 {
		t.Fatalf("cpu=%v want 0", cpu)
	}
}

func TestParseProcStatCPUTime(t *testing.T) {
	// utime=120 and stime=30 ticks at 100Hz => 1.5 seconds.
	stat := "12 (code) S 7 12 12 0 0 0 0 0 0 0 120 30 0 0 20 0 1 0 0 12345"
	_, _, _, cpu := parseProcStat(stat, time.Unix(1_000_000, 0), 100)
	if cpu != 1500*time.Millisecond {
		t.Fatalf("cpu=%v want 1.5s", cpu)
	}
}

func TestParseProcStatCommWithParens(t *testing.T) {
	stat := "1 (a) b) (c) S 0 1 1 0 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0"
	ppid, comm, _, _ := parseProcStat(stat, time.Unix(0, 0), 100)
	if comm != "a) b) (c" {
		t.Fatalf("comm=%q", comm)
	}
	if ppid != 0 {
		t.Fatalf("ppid=%d", ppid)
	}
}

func TestParseProcStatmRSS(t *testing.T) {
	if got := parseProcStatm("10 4 1 1 0 1 0", 4096); got != 4*4096 {
		t.Fatalf("rss=%d", got)
	}
	if parseProcStatm("10", 4096) != 0 {
		t.Fatal("short statm should be 0")
	}
}

func TestParseProcStatLongRunningProcess(t *testing.T) {
	const hz = 100
	const elapsed = 4 * 365 * 24 * time.Hour
	boot := time.Unix(1_000_000, 0)
	ticks := int64(elapsed/time.Second) * hz
	stat := fmt.Sprintf("12 (code) S 7 12 12 0 0 0 0 0 0 0 %d 30 0 0 20 0 1 0 %d", ticks, ticks)
	_, _, start, cpu := parseProcStat(stat, boot, hz)
	if !start.Equal(boot.Add(elapsed)) || cpu != elapsed+300*time.Millisecond {
		t.Fatalf("start=%v cpu=%v, want %v and %v", start, cpu, boot.Add(elapsed), elapsed+300*time.Millisecond)
	}
}
