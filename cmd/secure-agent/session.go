package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
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
	if err := runSession(client, arg, format, os.Stdout); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runSession(client *http.Client, arg, format string, out io.Writer) error {
	code, body, err := sessionRequest(client, sessionReportURL(arg, format))
	if err != nil {
		return fmt.Errorf("session failed: %w", err)
	}
	if code == http.StatusNotFound {
		if !utf8.ValidString(arg) {
			return fmt.Errorf("session id prefix must be valid UTF-8")
		}
		if utf8.RuneCountInString(arg) < minSessionPrefix {
			return fmt.Errorf("no session %q (an id prefix needs at least %d characters)", arg, minSessionPrefix)
		}
		id, err := resolveSessionPrefix(client, arg)
		if err != nil {
			return err
		}
		code, body, err = sessionRequest(client, sessionReportURL(id, format))
		if err != nil {
			return fmt.Errorf("session failed: %w", err)
		}
	}
	if code != http.StatusOK {
		return fmt.Errorf("session failed (%d): %s", code, strings.TrimSpace(body))
	}
	if _, err := io.WriteString(out, body); err != nil {
		return err
	}
	if !strings.HasSuffix(body, "\n") {
		_, err := io.WriteString(out, "\n")
		return err
	}
	return nil
}

func resolveSessionPrefix(client *http.Client, prefix string) (string, error) {
	q := url.Values{"prefix": []string{prefix}}
	code, body, err := sessionRequest(client, "http://unix/sessions/resolve?"+q.Encode())
	if err != nil {
		return "", fmt.Errorf("session prefix lookup unavailable: %w", err)
	}
	if code == http.StatusNotFound {
		return "", fmt.Errorf("daemon does not support session prefix lookup; use a full session ID or update daemon")
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("session prefix lookup unavailable (%d)", code)
	}
	var matches []sessionRow
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "[") || json.Unmarshal([]byte(trimmed), &matches) != nil || len(matches) > 2 {
		return "", fmt.Errorf("invalid session prefix response")
	}
	seen := make(map[string]bool, len(matches))
	var exact string
	for _, match := range matches {
		if match.ID == "" || !strings.HasPrefix(match.ID, prefix) || seen[match.ID] {
			return "", fmt.Errorf("invalid session prefix response")
		}
		seen[match.ID] = true
		if match.ID == prefix {
			exact = match.ID
		}
	}
	if exact != "" {
		return exact, nil
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no session matches %q", prefix)
	case 1:
		return matches[0].ID, nil
	default:
		return "", fmt.Errorf("%q matches multiple sessions (at least 2); use a longer prefix:\n  %s  %s  %s\n  %s  %s  %s",
			prefix,
			matches[0].ID, matches[0].Harness, sessionWhere(matches[0]),
			matches[1].ID, matches[1].Harness, sessionWhere(matches[1]))
	}
}

func sessionRequest(client *http.Client, path string) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func sessionReportURL(id, format string) string {
	return "http://unix/sessions/" + url.PathEscape(id) + "/report?format=" + format
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
