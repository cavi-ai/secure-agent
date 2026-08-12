//go:build darwin

package agents

import (
	"bytes"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type DarwinProcSource struct{}

func NewDarwinProcSource() ProcSource {
	return &DarwinProcSource{}
}

func (d *DarwinProcSource) List() []ProcInfo {
	kprocs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}

	res := make([]ProcInfo, 0, len(kprocs))
	for _, kp := range kprocs {
		pid := kp.Proc.P_pid
		ppid := kp.Eproc.Ppid

		exe := getProcPath(pid)
		res = append(res, ProcInfo{
			PID:  pid,
			PPID: ppid,
			Exe:  exe,
		})
	}
	return res
}

func (d *DarwinProcSource) Info(pid int32) (ProcInfo, bool) {
	kprocs, err := unix.SysctlKinfoProcSlice("kern.proc.pid", int(pid))
	if err != nil || len(kprocs) == 0 {
		return ProcInfo{}, false
	}
	kp := kprocs[0]

	exe := getProcPath(pid)
	return ProcInfo{
		PID:  pid,
		PPID: kp.Eproc.Ppid,
		Exe:  exe,
	}, true
}

func getProcPath(pid int32) string {
	buf := make([]byte, 1024)
	// SYS_PROC_INFO = 338, PROC_INFO_CALL_PIDPATH = 11
	r1, _, err := syscall.Syscall6(338, 11, uintptr(pid), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if err != 0 || r1 <= 0 {
		return ""
	}
	n := bytes.IndexByte(buf, 0)
	if n >= 0 {
		return string(buf[:n])
	}
	return string(buf[:r1])
}
