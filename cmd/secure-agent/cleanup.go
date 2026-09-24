package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// cleanupEntry and cleanupLedger mirror the daemon's GET /cleanup/ledger body.
type cleanupEntry struct {
	TS     time.Time `json:"ts"`
	Action string    `json:"action"`
	Path   string    `json:"path"`
	Repo   string    `json:"repo"`
	Bytes  int64     `json:"bytes"`
	Detail string    `json:"detail"`
}

type cleanupLedger struct {
	Totals  wtTotals       `json:"totals"`
	Entries []cleanupEntry `json:"entries"`
}

// clItem and clReport mirror the daemon's GET /cleanup body.
type clItem struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Project     string `json:"project"`
	SizeBytes   int64  `json:"size_bytes"`
	SizePartial bool   `json:"size_partial"`
	LastTouched string `json:"last_touched"`
	IdleDays    int    `json:"idle_days"`
	Action      string `json:"action"`
	Command     string `json:"command"`
	Note        string `json:"note"`
}

type clReport struct {
	Sizing bool     `json:"sizing"`
	Items  []clItem `json:"items"`
	Kinds  []struct {
		Kind  string `json:"kind"`
		Bytes int64  `json:"bytes"`
		Count int    `json:"count"`
	} `json:"kinds"`
	Reclaimed *wtTotals `json:"reclaimed"`
	// Advice is the local advisor's plan per project ("machine" for
	// machine-wide caches).
	Advice map[string]struct {
		Rationale       string `json:"rationale"`
		SuggestedAction string `json:"suggested_action"`
	} `json:"advice"`
}

func handleCleanup(client *http.Client) {
	c := *client
	c.Timeout = wtScanTimeout + 10*time.Minute // a tool clean runs up to 10 minutes
	if err := runCleanup(os.Stdout, &c, os.Args[2:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runCleanup dispatches `cleanup [log|trash|clean]` and the inventory view.
func runCleanup(w io.Writer, client *http.Client, args []string) error {
	if len(args) > 0 && (args[0] == "trash" || args[0] == "clean") {
		return runCleanupAction(w, client, args)
	}
	if len(args) > 0 && args[0] == "advise" {
		return runCleanupAdvise(w, client, args)
	}
	if len(args) == 0 || args[0] != "log" {
		return runCleanupList(w, client, args)
	}
	code, body := request(client, http.MethodGet, "http://unix/cleanup/ledger?limit="+queryFlag(args, "--limit", "50"), "")
	if code == http.StatusForbidden {
		return fmt.Errorf("cleanup log refused (403): agent sessions cannot read the cleanup ledger")
	}
	if code != 200 {
		return fmt.Errorf("cleanup log failed (%d): %s", code, strings.TrimSpace(body))
	}
	if slices.Contains(args, "--json") {
		fmt.Fprintln(w, body)
		return nil
	}
	var l cleanupLedger
	if err := json.Unmarshal([]byte(body), &l); err != nil {
		return fmt.Errorf("cleanup log: unreadable response: %v", err)
	}
	home, _ := os.UserHomeDir()
	fmt.Fprint(w, formatCleanupLog(l, home, time.Local))
	return nil
}

func formatCleanupLog(l cleanupLedger, home string, loc *time.Location) string {
	var b strings.Builder
	for _, e := range l.Entries {
		size := "-"
		if e.Bytes > 0 {
			size = humanBytes(e.Bytes)
		}
		fmt.Fprintf(&b, "%s  %-16s  %9s  %s\n", e.TS.In(loc).Format("2006-01-02 15:04"), e.Action, size, tildePath(e.Path, home))
	}
	t := l.Totals
	fmt.Fprintf(&b, "reclaimed %s over %s; %s in the last 30 days\n",
		humanBytes(t.Bytes), plural(t.Count, "cleanup", "cleanups"), humanBytes(t.Bytes30d))
	return b.String()
}

func runCleanupList(w io.Writer, client *http.Client, args []string) error {
	path := "http://unix/cleanup"
	if slices.Contains(args, "--refresh") {
		path += "?refresh=1"
	}
	code, body := request(client, http.MethodGet, path, "")
	if code == http.StatusForbidden {
		return fmt.Errorf("cleanup refused (403): agent sessions cannot read the cleanup inventory")
	}
	if code != 200 {
		return fmt.Errorf("cleanup failed (%d): %s", code, strings.TrimSpace(body))
	}
	if slices.Contains(args, "--json") {
		fmt.Fprintln(w, body)
		return nil
	}
	var rep clReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		return fmt.Errorf("cleanup: unreadable response: %v", err)
	}
	home, _ := os.UserHomeDir()
	fmt.Fprint(w, formatCleanup(rep, queryFlag(args, "--kind", ""), queryFlag(args, "--project", ""), home))
	return nil
}

// formatCleanup prints one line per item (biggest first, as the daemon
// sorts), the note and the way to clear it, then the per-kind totals.
func formatCleanup(rep clReport, kind, project, home string) string {
	var b strings.Builder
	for _, it := range rep.Items {
		if (kind != "" && it.Kind != kind) || (project != "" && !strings.Contains(it.Project, project)) {
			continue
		}
		size := "-"
		if it.SizeBytes > 0 {
			size = humanBytes(it.SizeBytes)
			if it.SizePartial {
				size = "≥" + size
			}
		}
		idle := "-"
		if it.LastTouched != "" {
			idle = fmt.Sprintf("%dd", it.IdleDays)
		}
		fmt.Fprintf(&b, "  %-10s  %9s  %5s  %s\n", it.Kind, size, idle, tildePath(it.Path, home))
		how := ""
		switch it.Action {
		case "trash":
			how = "clear: secure-agent cleanup trash " + tildePath(it.Path, home)
		case "clean":
			how = "clear: secure-agent cleanup clean " + quoteIfSpaced(it.Name) + "  (runs `" + it.Command + "`)"
		}
		for _, line := range []string{it.Note, how} {
			if line != "" {
				fmt.Fprintf(&b, "              %s\n", line)
			}
		}
	}
	var parts []string
	for _, k := range rep.Kinds {
		parts = append(parts, fmt.Sprintf("%s %s (%d)", k.Kind, humanBytes(k.Bytes), k.Count))
	}
	b.WriteString(strings.Join(parts, " · "))
	if rep.Sizing {
		b.WriteString(" · still measuring: lower bounds")
	}
	b.WriteString("\n")
	projects := make([]string, 0, len(rep.Advice))
	for p := range rep.Advice {
		if project == "" || strings.Contains(p, project) {
			projects = append(projects, p)
		}
	}
	sort.Strings(projects)
	for _, p := range projects {
		a := rep.Advice[p]
		fmt.Fprintf(&b, "advisor on %s: %s\n", tildePath(p, home), a.Rationale)
		for _, step := range strings.Split(a.SuggestedAction, "\n") {
			if step != "" {
				fmt.Fprintf(&b, "  - %s\n", step)
			}
		}
	}
	if t := rep.Reclaimed; t != nil && t.TrashedCount > 0 {
		fmt.Fprintf(&b, "in the Trash from cleanups: %s over %s (the space frees when the Trash is emptied)\n",
			humanBytes(t.TrashedBytes), plural(t.TrashedCount, "item", "items"))
	}
	return b.String()
}

// runCleanupAdvise asks the local advisor for a cleanup plan for one
// project: a repository path, or "machine" for machine-wide caches.
func runCleanupAdvise(w io.Writer, client *http.Client, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: secure-agent cleanup advise <repository path | machine>")
	}
	project := args[1]
	if project != "machine" {
		abs, err := filepath.Abs(project)
		if err != nil {
			return err
		}
		project = abs
	}
	body, _ := json.Marshal(map[string]string{"project": project})
	code, resp := request(client, http.MethodPost, "http://unix/cleanup/advise", string(body))
	switch {
	case code == http.StatusForbidden:
		return fmt.Errorf("cleanup advise refused (403): while the menu bar app runs, changes go through it — use the console's Cleanup tab; agent sessions cannot make changes")
	case code != 200:
		return fmt.Errorf("cleanup advise failed (%d): %s", code, strings.TrimSpace(resp))
	}
	var out struct {
		Queued bool `json:"queued"`
	}
	_ = json.Unmarshal([]byte(resp), &out)
	if !out.Queued {
		return fmt.Errorf("not queued: the advisor is off or its queue is full")
	}
	fmt.Fprintf(w, "asked the advisor for a cleanup plan for %s; it shows in `secure-agent cleanup` once the local model answers\n", project)
	return nil
}

func quoteIfSpaced(s string) string {
	if strings.Contains(s, " ") {
		return "'" + s + "'"
	}
	return s
}

// runCleanupAction: `cleanup trash <path>` or `cleanup clean <tool>`.
func runCleanupAction(w io.Writer, client *http.Client, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: secure-agent cleanup trash <path> | cleanup clean <tool>")
	}
	field, key := "name", strings.Join(args[1:], " ")
	if args[0] == "trash" {
		abs, err := filepath.Abs(args[1])
		if err != nil {
			return err
		}
		field, key = "path", abs
	}
	body, _ := json.Marshal(map[string]string{field: key})
	code, resp := request(client, http.MethodPost, "http://unix/cleanup/"+args[0], string(body))
	switch {
	case code == http.StatusForbidden:
		return fmt.Errorf("cleanup %s refused (403): while the menu bar app runs, changes go through it — use the console's Worktrees tab; agent sessions cannot make changes", args[0])
	case code != 200:
		return fmt.Errorf("cleanup %s failed (%d): %s", args[0], code, strings.TrimSpace(resp))
	}
	var out struct {
		Result struct {
			Bytes   int64  `json:"bytes"`
			TrashAt string `json:"trash_path"`
		} `json:"result"`
	}
	_ = json.Unmarshal([]byte(resp), &out)
	if args[0] == "trash" {
		fmt.Fprintf(w, "moved %s to the Trash (%s; frees when the Trash is emptied)\n", key, humanBytes(out.Result.Bytes))
	} else {
		fmt.Fprintf(w, "cleaned %s: %s reclaimed\n", key, humanBytes(out.Result.Bytes))
	}
	return nil
}
