//go:build linux

package agents

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcProcSource reads /proc: pid/ppid/comm from stat, exe from the
// /proc/<pid>/exe symlink (read lazily, matching the darwin source's
// cheap-List / lazy-Info split).
type ProcProcSource struct{}

func NewProcProcSource() ProcSource { return &ProcProcSource{} }

// NewProcSource returns the platform's process source.
func NewProcSource() ProcSource { return &ProcProcSource{} }

func (p *ProcProcSource) List() []ProcInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	res := make([]ProcInfo, 0, len(entries)/4)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		ppid, comm := readStat(int32(pid))
		res = append(res, ProcInfo{PID: int32(pid), PPID: ppid, Comm: comm})
	}
	return res
}

func (p *ProcProcSource) Info(pid int32) (ProcInfo, bool) {
	ppid, comm := readStat(pid)
	exe, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(int(pid)), "exe"))
	if comm == "" && exe == "" {
		return ProcInfo{}, false
	}
	return ProcInfo{PID: pid, PPID: ppid, Comm: comm, Exe: exe}, true
}

// readStat parses /proc/<pid>/stat for (ppid, comm). comm is in parens and may
// itself contain spaces/parens, so split at the LAST ')'.
func readStat(pid int32) (int32, string) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return 0, ""
	}
	s := string(b)
	open := strings.IndexByte(s, '(')
	close_ := strings.LastIndexByte(s, ')')
	if open < 0 || close_ <= open {
		return 0, ""
	}
	comm := s[open+1 : close_]
	// Fields after ')' start at field 3 (state); field 4 is ppid.
	rest := strings.Fields(s[close_+1:])
	ppid := int32(0)
	if len(rest) >= 2 {
		if v, err := strconv.ParseInt(rest[1], 10, 32); err == nil {
			ppid = int32(v)
		}
	}
	return ppid, comm
}
