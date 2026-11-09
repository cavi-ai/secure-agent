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

	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func handleLocalServices(client *http.Client, args []string) {
	if err := runLocalServices(client, args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, terminalSafe(err.Error()))
		os.Exit(1)
	}
}

func runLocalServices(client *http.Client, args []string, out io.Writer) error {
	query := url.Values{}
	asJSON := false
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
		default:
			return errors.New("usage: secure-agent local-services [--endpoint <loopback-url>] [--json]")
		}
	}
	code, body := request(client, http.MethodGet, "http://unix/local-services?"+query.Encode(), "")
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
	_, err := io.WriteString(out, b.String())
	return err
}
