package localservice

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

const maxListeners = 128

// Inventory is a bounded snapshot of visible TCP listeners. Process names are
// hints, not executable identities. Arguments and environment are never read.
type Inventory struct {
	State     string     `json:"state"`
	Scope     string     `json:"scope"`
	Truncated bool       `json:"truncated"`
	Listeners []Listener `json:"listeners"`
}

type Listener struct {
	PID      int    `json:"pid"`
	Command  string `json:"command"`
	Address  string `json:"address"`
	Binding  string `json:"binding"`
	Runtime  string `json:"runtime_hint"`
	Endpoint string `json:"candidate_endpoint,omitempty"`
}

func emptyInventory(state string) Inventory {
	return Inventory{State: state, Scope: "visible TCP listeners only; permissions, containers and scan limits can hide listeners; process names are unverified hints", Listeners: []Listener{}}
}

// DiscoverListeners invokes the native lsof inventory without a shell. Missing
// tools, timeouts and output limits stay visible instead of becoming no servers.
func DiscoverListeners(parent context.Context) Inventory {
	bin, err := exec.LookPath("lsof")
	if err != nil {
		bin = "/usr/sbin/lsof"
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-nP", "+c0", "-iTCP", "-sTCP:LISTEN", "-Fpcftn")
	cmd.WaitDelay = 100 * time.Millisecond
	stdout, stderr := &boundedOutput{}, &boundedOutput{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	result := parseListeners(stdout.data)
	result.Truncated = result.Truncated || stdout.full
	if ctx.Err() != nil || err != nil || len(stderr.data) != 0 || stderr.full || stdout.full {
		result.State = "partial"
		if len(result.Listeners) == 0 {
			result.State = "unavailable"
		}
		// lsof uses exit 1 with no output or diagnostic when no sockets match.
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && ctx.Err() == nil && len(stdout.data) == 0 && len(stderr.data) == 0 {
			result.State = "available"
		}
	}
	return result
}

type boundedOutput struct {
	data []byte
	full bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maxBody - len(b.data)
	if n > remaining {
		b.full = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil // discard excess while the process deadline bounds execution
}

func parseListeners(raw []byte) Inventory {
	result := emptyInventory("available")
	pid, command, family := 0, "", ""
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
			command, family = "", ""
		case 'c':
			command = line[1:]
			if len(command) > 256 {
				command = command[:256]
			}
		case 'f':
			family = ""
		case 't':
			family = line[1:]
		case 'n':
			host, port, err := net.SplitHostPort(line[1:])
			n, portErr := strconv.Atoi(port)
			if err != nil || portErr != nil || n < 1 || n > 65535 || pid <= 0 || (family != "IPv4" && family != "IPv6") {
				result.State = "partial"
				continue
			}
			if host == "*" {
				host = "0.0.0.0"
				if family == "IPv6" {
					host = "::"
				}
			}
			ip := net.ParseIP(host)
			if ip == nil {
				result.State = "partial"
				continue
			}
			listener := Listener{PID: pid, Command: command, Address: net.JoinHostPort(host, port), Binding: "non_loopback", Runtime: runtimeHint(command)}
			if ip.IsLoopback() {
				listener.Binding, listener.Endpoint = "loopback", "http://"+listener.Address
			} else if ip.IsUnspecified() {
				listener.Binding = "wildcard"
				host = "127.0.0.1"
				if family == "IPv6" {
					host = "::1"
				}
				listener.Endpoint = "http://" + net.JoinHostPort(host, port)
			}
			key := strconv.Itoa(pid) + "/" + listener.Address
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(result.Listeners) == maxListeners {
				result.Truncated = true
				continue
			}
			result.Listeners = append(result.Listeners, listener)
		}
	}
	if scanner.Err() != nil || len(raw) >= maxBody || result.Truncated {
		result.State = "partial"
		result.Truncated = true
	}
	slices.SortFunc(result.Listeners, func(a, b Listener) int {
		if a.PID != b.PID {
			return a.PID - b.PID
		}
		return strings.Compare(a.Address, b.Address)
	})
	return result
}

func runtimeHint(command string) string {
	switch strings.ToLower(command) {
	case "ollama":
		return "ollama"
	case "llama-server", "llama-server.exe":
		return "llama.cpp"
	case "mlx-agent", "mlx_lm.server":
		return "mlx"
	}
	return "unknown"
}

func selectEndpoints(configured []string, inventory Inventory) ([]string, int, error) {
	candidates := append([]string{}, configured...)
	for _, listener := range inventory.Listeners {
		if listener.Endpoint != "" && listener.Runtime != "unknown" {
			candidates = append(candidates, listener.Endpoint)
		}
	}
	candidates = append(candidates, DefaultEndpoints()...)
	for _, listener := range inventory.Listeners {
		if listener.Endpoint != "" {
			candidates = append(candidates, listener.Endpoint)
		}
	}
	selected := []string{}
	seen, omitted := map[string]bool{}, 0
	for _, candidate := range candidates {
		u, err := endpointURL(candidate)
		if err != nil {
			return nil, 0, err
		}
		if seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		if len(selected) == MaxEndpoints {
			omitted++
		} else {
			selected = append(selected, u.String())
		}
	}
	return selected, omitted, nil
}
