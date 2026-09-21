//go:build darwin

package agents

import (
	"bytes"
	"encoding/binary"
	"strings"
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

	rss, cpu := procUsage(pid)
	return ProcInfo{
		PID:       pid,
		PPID:      ppid,
		Comm:      commStr,
		Exe:       exe,
		StartTime: start,
		RSSBytes:  rss,
		CPUTime:   cpu,
		CWD:       procCWD(pid),
	}, true
}

func timevalToTime(tv unix.Timeval) time.Time {
	if tv.Sec == 0 && tv.Usec == 0 {
		return time.Time{}
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*1000)
}

// procUsage reads resident set size and cumulative CPU time via
// PROC_PIDTASKINFO. cgo is disabled;
// SYS_PROC_INFO is the libproc-equivalent syscall. A failure returns 0 so
// the UI can omit unavailable measurements rather than inventing values.
func procUsage(pid int32) (uint64, time.Duration) {
	var info struct {
		VirtualSize   uint64
		ResidentSize  uint64
		TotalUser     uint64
		TotalSystem   uint64
		ThreadsUser   uint64
		ThreadsSystem uint64
		_             [48]byte
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
		return 0, 0
	}
	return info.ResidentSize, time.Duration(info.TotalUser + info.TotalSystem)
}

// procCWD reads the current working directory from PROC_PIDVNODEPATHINFO.
// The first vnode_info_path is pvi_cdir; its path starts after vnode_info.
func procCWD(pid int32) string {
	const (
		procInfoCallPidInfo  = 2
		procPidVnodePathInfo = 9
		vnodeInfoSize        = 152
		maxPathLen           = 1024
		vnodePathInfoSize    = vnodeInfoSize + maxPathLen
	)
	var info [2 * vnodePathInfoSize]byte
	n, _, errno := unix.RawSyscall6(
		unix.SYS_PROC_INFO,
		uintptr(procInfoCallPidInfo),
		uintptr(pid),
		uintptr(procPidVnodePathInfo),
		0,
		uintptr(unsafe.Pointer(&info[0])),
		uintptr(len(info)),
	)
	if errno != 0 || n < uintptr(vnodeInfoSize) {
		return ""
	}
	path := info[vnodeInfoSize:vnodePathInfoSize]
	if end := bytes.IndexByte(path, 0); end >= 0 {
		path = path[:end]
	}
	return string(path)
}

// procArgs2 fetches the KERN_PROCARGS2 buffer: argc, exec path, argv, env.
func procArgs2(pid int32) []byte {
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
		return nil
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
		return nil
	}
	return buf
}

func getProcPath(pid int32) string {
	buf := procArgs2(pid)
	if len(buf) <= 4 {
		return ""
	}
	pathBuf := buf[4:]
	idx := bytes.IndexByte(pathBuf, 0)
	if idx > 0 {
		return string(pathBuf[:idx])
	}
	return ""
}

// ProcEnvVar reads one variable from a process's start environment out of
// the KERN_PROCARGS2 buffer (the env block follows argv) — the same
// mechanism and the same same-user visibility limit as `ps eww`. "" when
// unreadable or unset.
func ProcEnvVar(pid int32, key string) string {
	buf := procArgs2(pid)
	if len(buf) <= 4 {
		return ""
	}
	argc := int(int32(binary.LittleEndian.Uint32(buf[:4])))
	rest := buf[4:]
	next := func() (string, bool) {
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			return "", false
		}
		s := string(rest[:i])
		rest = rest[i+1:]
		return s, true
	}
	if _, ok := next(); !ok { // exec path
		return ""
	}
	for len(rest) > 0 && rest[0] == 0 { // alignment padding
		rest = rest[1:]
	}
	for i := 0; i < argc; i++ { // argv[0..argc-1]
		if _, ok := next(); !ok {
			return ""
		}
	}
	for len(rest) > 0 && rest[0] == 0 { // argv/env separator + padding
		rest = rest[1:]
	}
	prefix := key + "="
	for len(rest) > 0 {
		s, ok := next()
		if !ok {
			s = string(rest)
			rest = nil
		}
		if strings.HasPrefix(s, prefix) {
			return s[len(prefix):]
		}
	}
	return ""
}

// NewProcSource returns the platform's process source.
func NewProcSource() ProcSource { return NewDarwinProcSource() }
