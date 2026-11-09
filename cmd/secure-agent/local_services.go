package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func handleLocalServices(client *http.Client, args []string) {
	if err := runLocalServices(client, args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, terminalSafe(err.Error()))
		os.Exit(1)
	}
}

func runLocalServices(client *http.Client, args []string, out io.Writer) error {
	if len(args) > 0 && (args[0] == "remediate" || args[0] == "rollback" || args[0] == "receipt") {
		return runServiceRemediation(client, args, out)
	}
	if len(args) != 0 && args[0] == "create-key" {
		if len(args) != 2 {
			return errors.New("usage: secure-agent local-services create-key <absolute-path>")
		}
		if err := localservice.CreateKeyFile(args[1]); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Created an owner-only model API key file. Key contents were not printed.")
		return err
	}
	query := url.Values{}
	asJSON := false
	runtime := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--endpoint":
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "--") {
				return errors.New("--endpoint requires a loopback HTTP base URL")
			}
			query.Add("endpoint", args[i])
		case "--runtime":
			i++
			if i >= len(args) {
				return errors.New("--runtime requires ollama, llama.cpp, mlx or openai-compatible")
			}
			for _, profile := range localservice.HardeningProfiles() {
				if profile.Runtime == args[i] {
					runtime = args[i]
				}
			}
			if runtime != args[i] {
				return errors.New("unsupported hardening runtime; use ollama, llama.cpp, mlx or openai-compatible")
			}
		default:
			return errors.New("usage: secure-agent local-services [--endpoint <loopback-url>] [--runtime <runtime>] [--json]")
		}
	}
	assessmentClient := *client
	assessmentClient.Timeout = 8 * time.Second // native inventory (2s) + metadata (4s) + response
	code, body := request(&assessmentClient, http.MethodGet, "http://unix/local-services?"+query.Encode(), "")
	if code != http.StatusOK {
		return fmt.Errorf("local service assessment failed (%d): %s", code, terminalSafe(strings.TrimSpace(body)))
	}
	var report localservice.Report
	if err := json.Unmarshal([]byte(body), &report); err != nil || report.Enforcement != "not_assessed" {
		return errors.New("local service assessment response is unreadable or unsupported")
	}
	if asJSON {
		_, err := fmt.Fprintln(out, body)
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Scope: %s\nEnforcement: not assessed\n", terminalSafe(report.Scope))
	if report.Managed != nil {
		fmt.Fprintf(&b, "Managed advisor: %s; %s; %s\n", terminalSafe(report.Managed.State), terminalSafe(report.Managed.Transport), terminalSafe(report.Managed.Enforcement))
	}
	if report.Inventory != nil {
		fmt.Fprintf(&b, "Listener inventory: %s; %d visible listeners; truncated: %t\n", terminalSafe(report.Inventory.State), len(report.Inventory.Listeners), report.Inventory.Truncated)
		fmt.Fprintf(&b, "Inventory scope: %s\n", terminalSafe(report.Inventory.Scope))
		for _, listener := range report.Inventory.Listeners {
			fmt.Fprintf(&b, "  PID %d %s %s (%s; runtime hint: %s)\n", listener.PID, terminalSafe(listener.Command), terminalSafe(listener.Address), terminalSafe(listener.Binding), terminalSafe(listener.Runtime))
		}
	}
	if report.Omitted > 0 {
		fmt.Fprintf(&b, "Not probed: %d additional endpoint candidates; select them with --endpoint.\n", report.Omitted)
	}
	for _, service := range report.Services {
		fmt.Fprintf(&b, "\n%s\n", terminalSafe(service.Endpoint))
		for _, entry := range []struct {
			name  string
			probe localservice.Probe
		}{{"Metadata", service.Metadata}, {"Foreign Origin", service.CrossOrigin}, {"Foreign Host", service.ForeignHost}} {
			fmt.Fprintf(&b, "  %s: %s", entry.name, terminalSafe(entry.probe.State))
			if entry.probe.Status != 0 {
				fmt.Fprintf(&b, " (HTTP %d)", entry.probe.Status)
			}
			if entry.probe.Sharing != "" {
				fmt.Fprintf(&b, "; sharing %s", terminalSafe(entry.probe.Sharing))
			}
			b.WriteByte('\n')
		}
		for _, finding := range service.Findings {
			fmt.Fprintf(&b, "  Review: %s\n", terminalSafe(finding))
		}
	}
	if runtime != "" {
		for _, profile := range localservice.HardeningProfiles() {
			if profile.Runtime != runtime {
				continue
			}
			fmt.Fprintf(&b, "\nHardening profile: %s (%s); not applied\n%s\n", profile.Title, profile.Support, profile.Settings)
			for _, step := range append(append(append([]string{}, profile.Steps...), profile.Verification...), profile.Limitations...) {
				fmt.Fprintf(&b, "  %s\n", step)
			}
		}
	}
	_, err := io.WriteString(out, b.String())
	return err
}
