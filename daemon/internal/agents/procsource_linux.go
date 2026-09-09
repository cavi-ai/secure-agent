//go:build linux

package agents

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcProcSource reads /proc: pid/ppid/comm/start from stat, exe from the
// /proc/<pid>/exe symlink (read lazily, matching the darwin source's
// cheap-List / lazy-Info split). RSS comes from statm on Info().
type ProcProcSource struct{}

func NewProcProcSource() ProcSource { return &ProcProcSource{} }

// NewProcSource returns the platform's process source.
func NewProcSource() ProcSource { return &ProcProcSource{} }

var (
	linuxBootOnce sync.Once
	linuxBoot     time.Time
	linuxHZ       int64 = 100 // Linux USER_HZ; /proc starttime is in these ticks.
)

func linuxClock() (time.Time, int64) {
	linuxBootOnce.Do(func() {
		linuxBoot = readBtime()
	})
	return linuxBoot, linuxHZ
}

func readBtime() time.Time {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		sec, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		if err != nil {
			return time.Time{}
		}
		return time.Unix(sec, 0)
	}
	return time.Time{}
}

func (p *ProcProcSource) List() []ProcInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	boot, hz := linuxClock()
	res := make([]ProcInfo, 0, len(entries)/4)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		ppid, comm, start := parseProcStat(string(raw), boot, hz)
		res = append(res, ProcInfo{PID: int32(pid), PPID: ppid, Comm: comm, StartTime: start})
	}
	return res
}

func (p *ProcProcSource) Info(pid int32) (ProcInfo, bool) {
	boot, hz := linuxClock()
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return ProcInfo{}, false
	}
	ppid, comm, start := parseProcStat(string(raw), boot, hz)
	exe, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(int(pid)), "exe"))
	if comm == "" && exe == "" {
		return ProcInfo{}, false
	}
	return ProcInfo{
		PID:       pid,
		PPID:      ppid,
		Comm:      comm,
		Exe:       exe,
		StartTime: start,
		RSSBytes:  readRSS(pid),
	}, true
}

func readRSS(pid int32) uint64 {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "statm"))
	if err != nil {
		return 0
	}
	return parseProcStatm(string(b), uint64(os.Getpagesize()))
}
