//go:build linux

package resource

import "testing"

func TestParseLinuxMeminfo(t *testing.T) {
	raw := parseLinuxMeminfo(`MemTotal:       16384000 kB
MemFree:         1048576 kB
MemAvailable:    4194304 kB
SwapTotal:       8388608 kB
SwapFree:        6291456 kB
`)
	if raw.TotalMemoryBytes != 16384000*1024 || raw.FreeMemoryBytes != 1048576*1024 || raw.AvailableMemoryBytes != 4194304*1024 {
		t.Fatalf("memory=%+v", raw)
	}
	if raw.SwapTotalBytes != 8388608*1024 || raw.SwapUsedBytes != 2097152*1024 {
		t.Fatalf("swap=%+v", raw)
	}
}

func TestParseLinuxMeminfoMarksAvailableMemoryUnknownWhenMissing(t *testing.T) {
	raw := parseLinuxMeminfo("MemTotal: 16384000 kB\nMemFree: 1048576 kB\n")
	if raw.AvailableMemoryKnown {
		t.Fatal("missing MemAvailable must remain unknown")
	}
}

func TestLinuxCollectorCarriesAvailableMemoryValidity(t *testing.T) {
	raw := (&linuxHostCollector{}).sample(nil)
	if raw.TotalMemoryBytes > 0 && !raw.AvailableMemoryKnown {
		t.Fatal("collector read total memory but dropped MemAvailable validity")
	}
}

func TestParseLinuxCPUTicks(t *testing.T) {
	ticks, ok := parseLinuxCPUTicks("cpu  100 5 50 800 20 10 5 0 0 0\n")
	if !ok || ticks.User != 100 || ticks.System != 50 || ticks.Idle != 820 || ticks.Other != 20 {
		t.Fatalf("ticks=%+v ok=%v", ticks, ok)
	}
}

func TestLinuxThermalState(t *testing.T) {
	if got := linuxThermalState(72_000); got != "nominal" {
		t.Fatalf("nominal=%q", got)
	}
	if got := linuxThermalState(86_000); got != "fair" {
		t.Fatalf("fair=%q", got)
	}
	if got := linuxThermalState(96_000); got != "serious" {
		t.Fatalf("serious=%q", got)
	}
	if got := linuxThermalState(105_000); got != "critical" {
		t.Fatalf("critical=%q", got)
	}
}
