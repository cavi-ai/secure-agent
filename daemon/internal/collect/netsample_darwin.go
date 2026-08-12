//go:build darwin

package collect

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type DarwinSocketLister struct{}

func NewDarwinSocketLister() SocketLister {
	return &DarwinSocketLister{}
}

func (d *DarwinSocketLister) SocketsFor(pid int32) []connKey {
	// Execute lsof for specific PID
	cmd := exec.Command("lsof", "-nP", "-iTCP", "-a", "-p", fmt.Sprintf("%d", pid))
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var res []connKey
	scanner := bufio.NewScanner(bytes.NewReader(out))

	for scanner.Scan() {
		line := scanner.Text()
		// Example line: node 1234 user 20u IPv4 0x... 0t0 TCP 192.168.1.10:54321->142.250.190.46:443 (ESTABLISHED)
		if !strings.Contains(line, "->") || !strings.Contains(line, "ESTABLISHED") {
			continue
		}

		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.Contains(f, "->") {
				parts := strings.Split(f, "->")
				if len(parts) == 2 {
					remote := parts[1]
					host, portStr, err := net.SplitHostPort(remote)
					if err == nil {
						port, _ := strconv.Atoi(portStr)
						res = append(res, connKey{
							PID:  pid,
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
