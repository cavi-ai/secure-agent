package main

// `secure-agent telemetry repair` — asks the menu bar app to re-register its
// file-telemetry helper, then waits for the daemon to report the helper's
// launchd job running. Only the app that registered the helper can register
// it again, so the CLI opens the app's repair URL instead of calling launchd.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const telemetryRepairURL = "secure-agent://telemetry/repair"

func handleTelemetry(client *http.Client, args []string) {
	if len(args) != 1 || args[0] != "repair" {
		fmt.Println("Usage: secure-agent telemetry repair")
		os.Exit(1)
	}
	openURL := func(url string) error { return exec.Command("/usr/bin/open", url).Run() }
	readState := func() (string, error) { return fetchESState(client) }
	os.Exit(telemetryRepair(os.Stdout, openURL, readState, 60*time.Second, time.Second))
}

// fetchESState returns `es_service.state` from the daemon's GET /status.
func fetchESState(client *http.Client) (string, error) {
	resp, err := client.Get("http://unix/status")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("secure-agentd answered /status with %d", resp.StatusCode)
	}
	var body struct {
		ESService *struct {
			State string `json:"state"`
		} `json:"es_service"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.ESService == nil {
		return "", errors.New("secure-agentd reports no file-telemetry service")
	}
	return body.ESService.State, nil
}

// esJobRunning reports whether a daemon `es_service.state` is a running job
// with no spawn or exit failure marker.
func esJobRunning(state string) bool {
	return strings.HasPrefix(state, "running") &&
		!strings.Contains(state, "spawn") && !strings.Contains(state, "exit")
}

// telemetryRepair opens the app's repair URL, then reads the service state
// every interval until it is running (exit 0) or timeout passes (exit 1,
// printing the last state).
func telemetryRepair(w io.Writer, openURL func(string) error, readState func() (string, error),
	timeout, interval time.Duration) int {
	if err := openURL(telemetryRepairURL); err != nil {
		fmt.Fprintf(w, "telemetry repair: could not open %s: %v\n", telemetryRepairURL, err)
		return 1
	}
	deadline := time.Now().Add(timeout)
	last := "no answer from secure-agentd"
	for {
		state, err := readState()
		switch {
		case err != nil:
			last = err.Error()
		case esJobRunning(state):
			fmt.Fprintf(w, "file telemetry: %s\n", state)
			return 0
		default:
			last = state
		}
		if !time.Now().Before(deadline) {
			fmt.Fprintf(w, "telemetry repair: the file-telemetry service is not running after %s; last state: %s\n", timeout, last)
			return 1
		}
		time.Sleep(interval)
	}
}
