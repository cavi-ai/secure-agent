//go:build darwin

package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type DarwinSocketLister struct{}

func NewDarwinSocketLister() SocketLister { return &DarwinSocketLister{} }
func NewSocketLister() SocketLister       { return NewDarwinSocketLister() }

func (d *DarwinSocketLister) SocketsFor(pid int32) []connKey {
	snapshot := d.Snapshot()
	if pid <= 0 {
		return snapshot.Connections
	}
	out := []connKey{}
	for _, c := range snapshot.Connections {
		if c.PID == pid {
			out = append(out, c)
		}
	}
	return out
}

type socketOutput struct {
	data []byte
	full bool
}

func (b *socketOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (1 << 20) - len(b.data)
	if len(p) > remaining {
		p = p[:remaining]
		b.full = true
	}
	b.data = append(b.data, p...)
	return n, nil
}

func (d *DarwinSocketLister) Snapshot() SocketSnapshot {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, lsofBinary(), "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-Fpcftn")
	cmd.WaitDelay = time.Second
	out, diagnostic := &socketOutput{}, &socketOutput{}
	cmd.Stdout, cmd.Stderr = out, diagnostic
	err := cmd.Run()
	snapshot := parseSocketFields(out.data)
	var exit *exec.ExitError
	empty := errors.As(err, &exit) && exit.ExitCode() == 1 && len(out.data) == 0 && len(diagnostic.data) == 0
	if (err != nil && !empty) || ctx.Err() != nil || len(diagnostic.data) > 0 || out.full || diagnostic.full {
		snapshot.State = "partial"
		if len(snapshot.Connections) == 0 {
			snapshot.State = "unavailable"
		}
	}
	return snapshot
}

func parseSocketFields(data []byte) SocketSnapshot {
	snapshot := SocketSnapshot{State: "available", Connections: []connKey{}}
	pid := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		if line[0] == 'p' {
			pid, _ = strconv.Atoi(line[1:])
			continue
		}
		if line[0] != 'n' {
			continue
		}
		local, remote, ok := strings.Cut(line[1:], "->")
		if !ok || pid <= 0 {
			snapshot.State = "partial"
			continue
		}
		lh, lp, le := net.SplitHostPort(local)
		rh, rp, re := net.SplitHostPort(remote)
		localPort, lerr := strconv.Atoi(lp)
		remotePort, rerr := strconv.Atoi(rp)
		if le != nil || re != nil || lerr != nil || rerr != nil || net.ParseIP(lh) == nil || net.ParseIP(rh) == nil {
			snapshot.State = "partial"
			continue
		}
		if len(snapshot.Connections) == 4096 {
			snapshot.State = "partial"
			break
		}
		snapshot.Connections = append(snapshot.Connections, connKey{PID: int32(pid), Host: rh, Port: remotePort, LocalHost: lh, LocalPort: localPort})
	}
	if scanner.Err() != nil {
		snapshot.State = "partial"
	}
	return snapshot
}
