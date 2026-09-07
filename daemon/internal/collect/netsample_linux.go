//go:build linux

package collect

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcSocketLister maps established TCP sockets to pids via /proc: the
// kernel's socket tables (/proc/net/tcp{,6}) give inode → remote endpoint,
// and /proc/<pid>/fd symlinks give pid → socket inode.
type ProcSocketLister struct{}

func NewProcSocketLister() SocketLister { return &ProcSocketLister{} }

// NewSocketLister returns the platform's socket lister.
func NewSocketLister() SocketLister { return NewProcSocketLister() }

func (l *ProcSocketLister) SocketsFor(pid int32) []connKey {
	conns := parseProcNetTCP("/proc/net/tcp")
	for inode, rc := range parseProcNetTCP("/proc/net/tcp6") {
		conns[inode] = rc
	}
	if len(conns) == 0 {
		return nil
	}

	var res []connKey
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		if pid > 0 && int32(p) != pid {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited or owned by another uid
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if rc, ok := conns[inode]; ok {
				res = append(res, connKey{PID: int32(p), Host: rc.host, Port: rc.port})
			}
		}
	}
	return res
}

type remoteConn struct {
	host string
	port int
}

// parseProcNetTCP reads a /proc/net/tcp{,6} table into inode → remote endpoint
// for ESTABLISHED sockets only (state 01).
func parseProcNetTCP(path string) map[string]remoteConn {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]remoteConn{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false // header row
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[3] != "01" {
			continue
		}
		hostHex, portHex, ok := strings.Cut(fields[2], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port == 0 {
			continue
		}
		host := hexToIP(hostHex)
		if host == "" {
			continue
		}
		out[fields[9]] = remoteConn{host: host, port: int(port)}
	}
	return out
}

// hexToIP decodes /proc's hex addresses: 8 chars = little-endian IPv4,
// 32 chars = IPv6 stored as four little-endian u32 words.
func hexToIP(h string) string {
	switch len(h) {
	case 8:
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
			if err != nil {
				return ""
			}
			b[3-i] = byte(v)
		}
		return net.IP(b).String()
	case 32:
		raw := make([]byte, 16)
		for i := 0; i < 16; i++ {
			v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
			if err != nil {
				return ""
			}
			raw[i] = byte(v)
		}
		b := make([]byte, 16)
		for w := 0; w < 4; w++ {
			b[w*4] = raw[w*4+3]
			b[w*4+1] = raw[w*4+2]
			b[w*4+2] = raw[w*4+1]
			b[w*4+3] = raw[w*4]
		}
		return net.IP(b).String()
	}
	return ""
}
