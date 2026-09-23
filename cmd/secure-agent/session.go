package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// sessionRow mirrors the fields of the daemon's GET /sessions rows that the
// CLI prints.
type sessionRow struct {
	ID         string     `json:"id"`
	Harness    string     `json:"harness"`
	Workspace  string     `json:"workspace,omitempty"`
	Repo       string     `json:"repo,omitempty"`
	Branch     string     `json:"branch,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	Status     string     `json:"status"`
}

// minSessionPrefix is the shortest id prefix `secure-agent session` resolves.
const minSessionPrefix = 6

// handleSessions lists sessions, narrowed by harness, repo, branch, since,
// status and limit.
func handleSessions(client *http.Client) {
	args := os.Args[2:]
	q := url.Values{}
	for _, name := range []string{"harness", "repo", "branch", "since", "status", "limit"} {
		if v := queryFlag(args, "--"+name, ""); v != "" {
			q.Set(name, v)
		}
	}
	code, body := request(client, http.MethodGet, "http://unix/sessions?"+q.Encode(), "")
	if code != 200 {
		fmt.Printf("sessions failed (%d): %s\n", code, strings.TrimSpace(body))
		os.Exit(1)
	}
	if slices.Contains(args, "--json") {
		fmt.Println(body)
		return
	}
	var rows []sessionRow
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		fmt.Printf("sessions: unreadable response: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(formatSessionsTable(rows))
}

// handleSession prints one session's report (markdown, or --json). The
// argument is a full id or a unique id prefix of at least six characters.
func handleSession(client *http.Client) {
	args := os.Args[2:]
	arg := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			arg = a
			break
		}
	}
	if arg == "" {
		fmt.Println("usage: secure-agent session <id-or-prefix> [--json]")
		os.Exit(1)
	}
	format := "md"
	if slices.Contains(args, "--json") {
		format = "json"
	}
	code, body := request(client, http.MethodGet, sessionReportURL(arg, format), "")
	if code == http.StatusNotFound {
		var known []sessionRow
		for _, path := range []string{"http://unix/sessions?limit=500", "http://unix/sessions?status=ended&limit=500"} {
			lcode, lbody := request(client, http.MethodGet, path, "")
			var rows []sessionRow
			if lcode == 200 && json.Unmarshal([]byte(lbody), &rows) == nil {
				known = append(known, rows...)
			}
		}
		id, msg, exit := resolveSessionID(arg, known)
		if exit != 0 {
			fmt.Print(msg)
			os.Exit(exit)
		}
		code, body = request(client, http.MethodGet, sessionReportURL(id, format), "")
	}
	if code != 200 {
		fmt.Printf("session failed (%d): %s\n", code, strings.TrimSpace(body))
		os.Exit(1)
	}
	fmt.Print(body)
	if !strings.HasSuffix(body, "\n") {
		fmt.Println()
	}
}

func sessionReportURL(id, format string) string {
	return "http://unix/sessions/" + url.PathEscape(id) + "/report?format=" + format
}

// resolveSessionID resolves arg against known sessions: an exact id wins,
// else a prefix of at least minSessionPrefix characters must match exactly
// one session. On failure it returns the message to print and exit code 1;
// an ambiguous prefix lists the candidates.
func resolveSessionID(arg string, known []sessionRow) (string, string, int) {
	seen := map[string]bool{}
	var matches []sessionRow
	for _, s := range known {
		if s.ID == arg {
			return s.ID, "", 0
		}
		if strings.HasPrefix(s.ID, arg) && !seen[s.ID] {
			seen[s.ID] = true
			matches = append(matches, s)
		}
	}
	if len(arg) < minSessionPrefix {
		return "", fmt.Sprintf("no session %q (an id prefix needs at least %d characters)\n", arg, minSessionPrefix), 1
	}
	switch len(matches) {
	case 0:
		return "", fmt.Sprintf("no session matches %q\n", arg), 1
	case 1:
		return matches[0].ID, "", 0
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%q matches %d sessions:\n", arg, len(matches))
		for _, s := range matches {
			fmt.Fprintf(&b, "  %s  %s  %s\n", s.ID, s.Harness, sessionWhere(s))
		}
		return "", b.String(), 1
	}
}

const sessionWhereMaxWidth = 48

// formatSessionsTable renders sessions as a fixed-width table: ID (first 8
// characters), harness, repo@branch (or workspace), local start, duration
// and status.
func formatSessionsTable(rows []sessionRow) string {
	harnessW, whereW := len("HARNESS"), len("REPO@BRANCH")
	for _, s := range rows {
		harnessW = max(harnessW, len([]rune(s.Harness)))
		whereW = max(whereW, len([]rune(sessionWhere(s))))
	}
	whereW = min(whereW, sessionWhereMaxWidth)
	var b strings.Builder
	fmt.Fprintf(&b, "%-8s  %-*s  %-*s  %-16s  %8s  %s\n", "ID", harnessW, "HARNESS", whereW, "REPO@BRANCH", "STARTED", "DURATION", "STATUS")
	for _, s := range rows {
		id := s.ID
		if r := []rune(id); len(r) > 8 {
			id = string(r[:8])
		}
		started := "—"
		if !s.StartedAt.IsZero() {
			started = s.StartedAt.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(&b, "%-8s  %-*s  %-*s  %-16s  %8s  %s\n", id, harnessW, s.Harness, whereW, clipRunes(sessionWhere(s), whereW),
			started, fmtSessionDuration(s), s.Status)
	}
	return b.String()
}

// sessionWhere is repo@branch, the repo alone, the workspace, or "—".
func sessionWhere(s sessionRow) string {
	switch {
	case s.Repo != "" && s.Branch != "":
		return s.Repo + "@" + s.Branch
	case s.Repo != "":
		return s.Repo
	case s.Workspace != "":
		return s.Workspace
	default:
		return "—"
	}
}

// fmtSessionDuration is started → ended (or → last seen) as "45s", "12m 5s"
// or "2h 3m".
func fmtSessionDuration(s sessionRow) string {
	end := s.LastSeenAt
	if s.EndedAt != nil {
		end = *s.EndedAt
	}
	if s.StartedAt.IsZero() || !end.After(s.StartedAt) {
		return "0s"
	}
	sec := int64(end.Sub(s.StartedAt) / time.Second)
	switch {
	case sec < 60:
		return fmt.Sprintf("%ds", sec)
	case sec < 3600:
		return fmt.Sprintf("%dm %ds", sec/60, sec%60)
	default:
		return fmt.Sprintf("%dh %dm", sec/3600, sec%3600/60)
	}
}
