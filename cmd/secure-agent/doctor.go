package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
)

// doctorCheck, doctorSummary and doctorReport mirror the daemon's GET /doctor
// body.
type doctorCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

type doctorSummary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

type doctorReport struct {
	GeneratedAt string        `json:"generated_at"`
	Version     string        `json:"version"`
	Uptime      string        `json:"uptime"`
	Grace       bool          `json:"grace"`
	Summary     doctorSummary `json:"summary"`
	Checks      []doctorCheck `json:"checks"`
}

// handleDoctor prints the daemon's self-check and exits 1 when any check
// fails, so CI can gate on it.
func handleDoctor(client *http.Client) {
	code, body := request(client, http.MethodGet, "http://unix/doctor", "")
	if code != 200 {
		fmt.Printf("doctor failed (%d): %s\n", code, strings.TrimSpace(body))
		os.Exit(1)
	}
	var rep doctorReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		fmt.Printf("doctor: unreadable response: %v\n", err)
		os.Exit(1)
	}
	out, exit := formatDoctor(rep)
	if slices.Contains(os.Args[2:], "--json") {
		fmt.Println(body)
	} else {
		fmt.Print(out)
	}
	os.Exit(exit)
}

// formatDoctor renders one line per check, an indented fix line under each
// failure, and a summary line. The exit code is 1 when any check failed.
func formatDoctor(rep doctorReport) (string, int) {
	var b strings.Builder
	for _, c := range rep.Checks {
		fmt.Fprintf(&b, "%-4s  %s", strings.ToUpper(c.State), c.Title)
		if c.Detail != "" {
			b.WriteString(" — " + c.Detail)
		}
		b.WriteByte('\n')
		if c.State == "fail" && c.Fix != "" {
			fmt.Fprintf(&b, "      fix: %s\n", c.Fix)
		}
	}
	fmt.Fprintf(&b, "%d pass · %d fail · %d skip\n", rep.Summary.Pass, rep.Summary.Fail, rep.Summary.Skip)
	if rep.Summary.Fail > 0 {
		return b.String(), 1
	}
	return b.String(), 0
}
