//go:build darwin

package collect

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type DarwinSocketLister struct{}

func NewDarwinSocketLister() SocketLister {
	return &DarwinSocketLister{}
}

func (d *DarwinSocketLister) SocketsFor(pid int32) []connKey {
	// If pid > 0, list for specific pid; if pid == 0 or -1, list system-wide established TCP sockets
	args := []string{"-nP", "-iTCP", "-sTCP:ESTABLISHED"}
	if pid > 0 {
		args = append(args, "-a", "-p", strconv.Itoa(int(pid)))
	}

	lsofBin := "lsof"
	if path, err := exec.LookPath("lsof"); err == nil {
		lsofBin = path
	} else if _, err := os.Stat("/usr/sbin/lsof"); err == nil {
		lsofBin = "/usr/sbin/lsof"
	}

	cmd := exec.Command(lsofBin, args...)
	out, _ := cmd.Output()
	if len(out) == 0 {
		return nil
	}

	var res []connKey
	scanner := bufio.NewScanner(bytes.NewReader(out))

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "->") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		var parsedPID int
		for idx := 1; idx < len(fields); idx++ {
			if val, err := strconv.Atoi(fields[idx]); err == nil && val > 0 {
				parsedPID = val
				break
			}
		}
		if parsedPID == 0 {
			continue
		}

		targetPID := pid
		if targetPID <= 0 {
			targetPID = int32(parsedPID)
		}

		for _, f := range fields {
			if strings.Contains(f, "->") {
				parts := strings.Split(f, "->")
				if len(parts) == 2 {
					remote := parts[1]
					host, portStr, err := net.SplitHostPort(remote)
					if err == nil {
						port, _ := strconv.Atoi(portStr)
						res = append(res, connKey{
							PID:  targetPID,
							Host: host,
							Port: port,
						})
					}
				}
			}
		}
	}

	return res
}
