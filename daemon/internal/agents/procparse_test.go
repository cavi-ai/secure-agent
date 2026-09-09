package agents

import (
	"testing"
	"time"
)

func TestParseProcStatStartAndPPID(t *testing.T) {
	// Minimal /proc/pid/stat: pid (comm) state ppid ... starttime at field 22.
	// After ')': state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt
	// utime stime cutime cstime priority nice numthreads itrealvalue starttime ...
	stat := "12 (code) S 7 12 12 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 12345"
	boot := time.Unix(1_000_000, 0)
	ppid, comm, start := parseProcStat(stat, boot, 100)
	if ppid != 7 || comm != "code" {
		t.Fatalf("ppid=%d comm=%q", ppid, comm)
	}
	want := boot.Add(12345 * time.Second / 100)
	if !start.Equal(want) {
		t.Fatalf("start=%v want %v", start, want)
	}
}

func TestParseProcStatCommWithParens(t *testing.T) {
	stat := "1 (a) b) (c) S 0 1 1 0 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0"
	ppid, comm, _ := parseProcStat(stat, time.Unix(0, 0), 100)
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
