//go:build darwin

package agents

import (
	"bytes"
	"time"
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
		commBuf := make([]byte, len(kp.Proc.P_comm))
		for i, c := range kp.Proc.P_comm {
			commBuf[i] = byte(c)
		}
		n := bytes.IndexByte(commBuf, 0)
		commStr := string(commBuf)
		if n >= 0 {
			commStr = string(commBuf[:n])
		}

		res = append(res, ProcInfo{
			PID:       kp.Proc.P_pid,
			PPID:      kp.Eproc.Ppid,
			Comm:      commStr,
			Exe:       "", // Lazy populated on demand by tagger for candidates
			StartTime: timevalToTime(kp.Proc.P_starttime),
		})
	}
	return res
}

func (d *DarwinProcSource) Info(pid int32) (ProcInfo, bool) {
	exe := getProcPath(pid)
	ppid := int32(0)
	commStr := ""
	start := time.Time{}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid)); err == nil {
		ppid = kp.Eproc.Ppid
		commBuf := make([]byte, len(kp.Proc.P_comm))
		for i, c := range kp.Proc.P_comm {
			commBuf[i] = byte(c)
		}
		n := bytes.IndexByte(commBuf, 0)
		commStr = string(commBuf)
		if n >= 0 {
			commStr = string(commBuf[:n])
		}
		start = timevalToTime(kp.Proc.P_starttime)
	} else if exe == "" {
		return ProcInfo{}, false
	}

	if exe == "" && commStr == "" {
		return ProcInfo{}, false
	}

	return ProcInfo{
		PID:       pid,
		PPID:      ppid,
		Comm:      commStr,
		Exe:       exe,
		StartTime: start,
		RSSBytes:  procRSS(pid),
	}, true
}

func timevalToTime(tv unix.Timeval) time.Time {
	if tv.Sec == 0 && tv.Usec == 0 {
		return time.Time{}
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*1000)
}

// procRSS reads resident set size via PROC_PIDTASKINFO. cgo is disabled;
// SYS_PROC_INFO is the libproc-equivalent syscall. A failure returns 0 so
// the UI can omit memory rather than invent a number.
func procRSS(pid int32) uint64 {
	var info struct {
		VirtualSize  uint64
		ResidentSize uint64
		_            [80]byte
	}
	const (
		procInfoCallPidInfo = 2
		procPidTaskInfo     = 4
	)
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PROC_INFO,
		uintptr(procInfoCallPidInfo),
		uintptr(pid),
		uintptr(procPidTaskInfo),
		0,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if errno != 0 {
		return 0
	}
	return info.ResidentSize
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

// NewProcSource returns the platform's process source.
func NewProcSource() ProcSource { return NewDarwinProcSource() }
