//go:build linux

package connpeer

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ClientPID returns the pid holding the client end of a loopback TCP
// connection to this process: the socket whose local address is remoteAddr
// in /proc/net/tcp{,6}, and the one other process with that socket open.
func ClientPID(remoteAddr string) (int32, error) {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, err
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil {
		return 0, fmt.Errorf("peer %s is not loopback", remoteAddr)
	}
	inode := ""
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if inode = socketInode(table, ip, p); inode != "" {
			break
		}
	}
	if inode == "" {
		return 0, fmt.Errorf("peer %s: no socket", remoteAddr)
	}
	pids := socketHolders("socket:["+inode+"]", os.Getpid())
	if len(pids) != 1 {
		return 0, fmt.Errorf("peer %s: %d candidate processes", remoteAddr, len(pids))
	}
	return pids[0], nil
}

// socketInode is the inode of the established socket whose local address is
// ip:port in a /proc/net/tcp table.
func socketInode(table string, ip net.IP, port int) string {
	f, err := os.Open(table)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[3] != "01" {
			continue
		}
		hostHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		if p, err := strconv.ParseInt(portHex, 16, 32); err != nil || int(p) != port {
			continue
		}
		if local := procIP(hostHex); local != nil && local.Equal(ip) {
			return fields[9]
		}
	}
	return ""
}

// procIP decodes /proc's hex address: 4 bytes for IPv4, 16 for IPv6, each
// 32-bit word in host (little-endian) order.
func procIP(h string) net.IP {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b)
}

// socketHolders are the pids, other than self, with link open as a file.
func socketHolders(link string, self int) []int32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int32
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name())); err == nil && l == link {
				out = append(out, int32(pid))
				break
			}
		}
	}
	return out
}
