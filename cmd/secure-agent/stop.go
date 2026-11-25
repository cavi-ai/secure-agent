package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	// defaultDBPath and defaultSocketPath are db_path and socket_path in
	// daemon/internal/config/defaults.yaml.
	defaultDBPath     = "~/.local/state/secure-agent/events.db"
	defaultSocketPath = "~/.config/secure-agent/daemon.sock"
	runRecordSuffix   = ".run-record.json"
	// stopWait bounds how long stop waits for the signalled daemon to exit.
	stopWait = 10 * time.Second
)

// daemonRun is the part of the daemon's run record that stop reads.
type daemonRun struct {
	PID    int    `json:"pid"`
	Ending string `json:"ending"`
}

// peerIdentity is the kernel's identity of the process serving the control socket.
type peerIdentity struct {
	PID     int
	Version uint32
}

func handleStop(sockPath string, args []string) {
	record := queryFlag(args, "--run-record", "")
	if record == "" {
		var err error
		if record, err = runRecordPath(); err != nil {
			fmt.Printf("stop: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(runStop(os.Stdout, sockPath, record, stopWait))
}

// runRecordPath resolves the daemon's run record path from its embedded
// defaults and the config overlay, as the daemon's RunRecordPath does.
func runRecordPath() (string, error) {
	db, sock := defaultDBPath, defaultSocketPath
	data, err := os.ReadFile(fleetEnrollConfigPath())
	switch {
	case err == nil:
		var overlay struct {
			DBPath     *string `yaml:"db_path"`
			SocketPath *string `yaml:"socket_path"`
		}
		if err := yaml.Unmarshal(data, &overlay); err != nil {
			return "", fmt.Errorf("config overlay: %w", err)
		}
		if overlay.DBPath != nil {
			db = *overlay.DBPath
		}
		if overlay.SocketPath != nil {
			sock = *overlay.SocketPath
		}
	case !errors.Is(err, fs.ErrNotExist):
		return "", err
	}
	for _, p := range []string{db, sock} {
		if p != "" {
			return expandConfigPath(p) + runRecordSuffix, nil
		}
	}
	return "", errors.New("config sets neither db_path nor socket_path")
}

// expandConfigPath expands a configured path as the daemon's config loader does.
func expandConfigPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return os.ExpandEnv(p)
}

// runStop signals only the pid in the run record at record, and only while
// the kernel reports that pid as the process serving sockPath.
func runStop(out io.Writer, sockPath, record string, wait time.Duration) int {
	data, err := os.ReadFile(record)
	if err != nil {
		fmt.Fprintf(out, "stop: no daemon run record: %v\n", err)
		return 1
	}
	var run daemonRun
	if err := json.Unmarshal(data, &run); err != nil || run.PID <= 0 {
		fmt.Fprintf(out, "stop: unreadable run record %s\n", record)
		return 1
	}
	if run.Ending != "" {
		fmt.Fprintf(out, "stop: secure-agentd is not running; its last run ended: %s\n", run.Ending)
		return 1
	}
	if ownedByApp(run.PID) {
		fmt.Fprintf(out, "stop: secure-agentd (pid %d) is run by the Secure Agent app, which restarts it when it exits; quit the app to stop it\n", run.PID)
		return 1
	}
	id, err := confirmDaemon(sockPath, run.PID)
	if err != nil {
		fmt.Fprintf(out, "stop: nothing stopped: %v\n", err)
		return 1
	}
	code, body, err := postStopIntent(sockPath, id)
	if err != nil {
		fmt.Fprintf(out, "stop: nothing stopped: stop intent not sent: %v\n", err)
		return 1
	}
	if code != http.StatusOK {
		fmt.Fprintf(out, "stop: nothing stopped: stop intent refused (%d): %s\n", code, strings.TrimSpace(body))
		return 1
	}
	if again, err := confirmDaemon(sockPath, run.PID); err != nil || again != id {
		fmt.Fprintf(out, "stop: nothing stopped: pid %d no longer serves %s\n", run.PID, sockPath)
		return 1
	}
	if err := syscall.Kill(id.PID, syscall.SIGTERM); err != nil {
		fmt.Fprintf(out, "stop: SIGTERM to pid %d failed: %v\n", id.PID, err)
		return 1
	}
	deadline := time.Now().Add(wait)
	for !errors.Is(syscall.Kill(id.PID, 0), syscall.ESRCH) {
		if time.Now().After(deadline) {
			fmt.Fprintf(out, "stop: sent SIGTERM to secure-agentd (pid %d); still running after %s\n", id.PID, wait)
			return 1
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintf(out, "Stopped secure-agentd (pid %d).\n", id.PID)
	return 0
}

func dialDaemon(ctx context.Context, sockPath string) (net.Conn, peerIdentity, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, peerIdentity{}, err
	}
	id, err := socketPeer(conn.(*net.UnixConn))
	if err != nil {
		conn.Close()
		return nil, peerIdentity{}, err
	}
	return conn, id, nil
}

// confirmDaemon requires the process serving sockPath to be pid.
func confirmDaemon(sockPath string, pid int) (peerIdentity, error) {
	conn, id, err := dialDaemon(context.Background(), sockPath)
	if err != nil {
		return peerIdentity{}, err
	}
	conn.Close()
	if id.PID != pid {
		return peerIdentity{}, fmt.Errorf("%s is served by pid %d, not the recorded daemon pid %d", sockPath, id.PID, pid)
	}
	return id, nil
}

// postStopIntent sends the stop intent only over a connection served by want.
func postStopIntent(sockPath string, want peerIdentity) (int, string, error) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, id, err := dialDaemon(ctx, sockPath)
			if err != nil {
				return nil, err
			}
			if id != want {
				conn.Close()
				return nil, fmt.Errorf("pid %d no longer serves %s", want.PID, sockPath)
			}
			return conn, nil
		},
	}}
	resp, err := client.Post("http://unix/daemon/stop-intent", "application/json", nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}
