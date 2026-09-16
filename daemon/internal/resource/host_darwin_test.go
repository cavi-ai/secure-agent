//go:build darwin

package resource

import (
	"encoding/binary"
	"testing"
)

func TestParseDarwinVMStat(t *testing.T) {
	free, available, compressed, known := parseDarwinVMStat(`Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free: 100.
Pages active: 200.
Pages inactive: 300.
Pages speculative: 20.
Pages purgeable: 10.
Pages occupied by compressor: 40.
`)
	if !known || free != 100*16384 || available != 420*16384 || compressed != 40*16384 {
		t.Fatalf("free=%d available=%d compressed=%d", free, available, compressed)
	}
}

func TestParseDarwinVMStatMarksAvailableMemoryUnknownWhenIncomplete(t *testing.T) {
	_, _, _, known := parseDarwinVMStat("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages active: 200.\n")
	if known {
		t.Fatal("incomplete vm_stat must not report available memory as known")
	}
}

func TestParseDarwinSwapUsage(t *testing.T) {
	raw := make([]byte, 32)
	binary.LittleEndian.PutUint64(raw[0:8], 8*gib)
	binary.LittleEndian.PutUint64(raw[8:16], 5*gib)
	binary.LittleEndian.PutUint64(raw[16:24], 3*gib)
	total, used := parseDarwinSwapUsage(raw)
	if total != 8*gib || used != 3*gib {
		t.Fatalf("total=%d used=%d", total, used)
	}
}

func TestDarwinCPUPercentUsesTickDelta(t *testing.T) {
	previous := cpuTicks{User: 100, System: 50, Idle: 850}
	current := cpuTicks{User: 140, System: 70, Idle: 890}
	got, ok := cpuPercentFromTicks(previous, current)
	if !ok || got != 60 {
		t.Fatalf("CPU=%v ok=%v want 60", got, ok)
	}
}

func TestParseDarwinProcessCPUAsWholeMachineShare(t *testing.T) {
	system, agent, ok := parseDarwinProcessCPU(" 10 12.5\n20 100.0\ninvalid\n", 8, map[int32]struct{}{20: {}})
	if !ok || system != 14.1 || agent != 12.5 {
		t.Fatalf("system=%v agent=%v ok=%v want 14.1, 12.5", system, agent, ok)
	}
}

func TestParseDarwinThermalState(t *testing.T) {
	if got := parseDarwinThermalState("CPU_Speed_Limit = 100\nCPU_Scheduler_Limit = 100\n"); got != "nominal" {
		t.Fatalf("nominal=%q", got)
	}
	if got := parseDarwinThermalState("CPU_Speed_Limit = 65\nCPU_Scheduler_Limit = 80\n"); got != "serious" {
		t.Fatalf("serious=%q", got)
	}
	if got := parseDarwinThermalState("Error: no thermal warning level"); got != "unknown" {
		t.Fatalf("unknown=%q", got)
	}
}
