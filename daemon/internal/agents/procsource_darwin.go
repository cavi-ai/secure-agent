//go:build darwin

package agents

import (
	"bytes"
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
		res = append(res, ProcInfo{
			PID:  kp.Proc.P_pid,
			PPID: kp.Eproc.Ppid,
			Exe:  "", // Lazy populated on demand by tagger
		})
	}
	return res
}

func (d *DarwinProcSource) Info(pid int32) (ProcInfo, bool) {
	exe := getProcPath(pid)
	if exe == "" {
		return ProcInfo{}, false
	}
	ppid := int32(0)
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid)); err == nil {
		ppid = kp.Eproc.Ppid
	}
	return ProcInfo{
		PID:  pid,
		PPID: ppid,
		Exe:  exe,
	}, true
}

func getProcPath(pid int32) string {
	mib := []int32{1 /* CTL_KERN */, 49 /* KERN_PROCARGS2 */, pid}
	n := uintptr(0)
	_, _, err := unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		0,
		uintptr(unsafe.Pointer(&n)),
		0,
		0,
	)
	if err != 0 || n == 0 {
		return ""
	}
	buf := make([]byte, n)
	_, _, err = unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n)),
		0,
		0,
	)
	if err != 0 || n <= 4 {
		return ""
	}
	pathBuf := buf[4:]
	idx := bytes.IndexByte(pathBuf, 0)
	if idx > 0 {
		return string(pathBuf[:idx])
	}
	return ""
}
