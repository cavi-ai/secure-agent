package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

func handleLocalInference(client *http.Client, args []string) {
	if err := runLocalInference(client, args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, terminalSafe(err.Error()))
		os.Exit(1)
	}
}
func runLocalInference(client *http.Client, args []string, out io.Writer) error {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		return errors.New("usage: secure-agent local-inference [--json]")
	}
	code, body := request(client, http.MethodGet, "http://unix/local-inference", "")
	if code != 200 {
		return fmt.Errorf("local inference monitoring unavailable (HTTP %d)", code)
	}
	if asJSON {
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, []byte(body), "", "  "); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, formatted.String())
		return err
	}
	var report struct {
		Coverage struct {
			Discovery, Connections, Requests string
			Truncated                        bool
			Pending                          int `json:"pending_endpoints"`
		} `json:"coverage"`
		Servers []struct {
			Endpoint, Runtime, Metadata string
			Models                      []struct{ Name string } `json:"loaded_models"`
		} `json:"servers"`
		Connections []struct {
			PID               int
			Process, Endpoint string
		} `json:"connections"`
		Requests []struct {
			ID, State, Model, Execution string
			PID                         int
		} `json:"requests"`
		Gateways []struct{ Listen, Upstream, State, Protection string } `json:"gateways"`
	}
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		return err
	}
	var text bytes.Buffer
	fmt.Fprintf(&text, "Coverage: discovery %s; connections %s; request tracking through configured gateways only.\n", terminalSafe(report.Coverage.Discovery), terminalSafe(report.Coverage.Connections))
	if report.Coverage.Truncated {
		fmt.Fprintln(&text, "Observation limits were reached; coverage is partial.")
	}
	if report.Coverage.Pending > 0 {
		fmt.Fprintf(&text, "%d endpoint candidates await another metadata batch.\n", report.Coverage.Pending)
	}
	for _, server := range report.Servers {
		fmt.Fprintf(&text, "Server: %s · %s · metadata %s\n", terminalSafe(server.Endpoint), terminalSafe(server.Runtime), terminalSafe(server.Metadata))
		for _, model := range server.Models {
			fmt.Fprintf(&text, "  Loaded: %s\n", terminalSafe(model.Name))
		}
	}
	for _, connection := range report.Connections {
		fmt.Fprintf(&text, "Connected: PID %d %s → %s\n", connection.PID, terminalSafe(connection.Process), terminalSafe(connection.Endpoint))
	}
	for _, r := range report.Requests {
		fmt.Fprintf(&text, "Request: %s · %s · PID %d · execution %s\n", terminalSafe(r.State), terminalSafe(r.Model), r.PID, terminalSafe(r.Execution))
	}
	for _, gateway := range report.Gateways {
		fmt.Fprintf(&text, "Gateway: %s → %s · %s; direct backend access remains outside gateway protection.\n", terminalSafe(gateway.Listen), terminalSafe(gateway.Upstream), terminalSafe(gateway.State))
	}
	_, err := out.Write(text.Bytes())
	return err
}
