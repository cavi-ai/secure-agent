package main

import (
	"strings"
	"testing"
	"time"
)

func TestFormatSessionsTable(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.Local)
	ended := start.Add(2*time.Hour + 3*time.Minute)
	rows := []sessionRow{
		{ID: "7f3a9c21-4b2e-4a1d", Harness: "claude", Repo: "api-service", Branch: "main", StartedAt: start, LastSeenAt: start.Add(12*time.Minute + 5*time.Second), Status: "active"},
		{ID: "abc", Harness: "opencode", Workspace: "/w/scratch", StartedAt: start, LastSeenAt: start, EndedAt: &ended, Status: "ended"},
		{ID: "s3", Harness: "codex", StartedAt: start, LastSeenAt: start.Add(45 * time.Second), Status: "idle"},
	}
	out := formatSessionsTable(rows)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want header + 3 rows, got %d lines:\n%s", len(lines), out)
	}
	for _, col := range []string{"ID", "HARNESS", "REPO@BRANCH", "STARTED", "DURATION", "STATUS"} {
		if !strings.Contains(lines[0], col) {
			t.Fatalf("header missing %q: %q", col, lines[0])
		}
	}
	for i, want := range [][]string{
		{"7f3a9c21", "claude", "api-service@main", "2026-09-01", "10:00", "12m", "5s", "active"},
		{"abc", "opencode", "/w/scratch", "2026-09-01", "10:00", "2h", "3m", "ended"},
		{"s3", "codex", "—", "2026-09-01", "10:00", "45s", "idle"},
	} {
		if got := strings.Fields(lines[i+1]); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("row %d = %q, want %q", i, got, want)
		}
	}
	// Fixed-width: every row's status starts in the STATUS column.
	statusCol := len([]rune(lines[0])) - len("STATUS")
	for i, l := range lines[1:] {
		if r := []rune(l); len(r) <= statusCol || r[statusCol] == ' ' {
			t.Fatalf("row %d status not in the STATUS column:\n%s", i, out)
		}
	}
}

func TestResolveSessionID(t *testing.T) {
	known := []sessionRow{
		{ID: "7f3a9c21-aaaa", Harness: "claude", Repo: "A", Branch: "main"},
		{ID: "7f3a9c21-bbbb", Harness: "codex"},
		{ID: "0b12cd34-cccc", Harness: "opencode"},
		{ID: "0b12cd34-cccc", Harness: "opencode"}, // live and ended listings can overlap
	}
	for name, tc := range map[string]struct {
		arg, id string
		exit    int
		msg     []string
	}{
		"unique prefix":     {arg: "0b12cd", id: "0b12cd34-cccc"},
		"exact id":          {arg: "7f3a9c21-aaaa", id: "7f3a9c21-aaaa"},
		"ambiguous":         {arg: "7f3a9c", exit: 1, msg: []string{`"7f3a9c" matches 2 sessions`, "7f3a9c21-aaaa  claude  A@main", "7f3a9c21-bbbb  codex  —"}},
		"none":              {arg: "ffffff", exit: 1, msg: []string{`no session matches "ffffff"`}},
		"prefix too short":  {arg: "0b12", exit: 1, msg: []string{"at least 6 characters"}},
		"short exact wins":  {arg: "0b12cd34-cccc", id: "0b12cd34-cccc"},
		"no known sessions": {arg: "abcdef", exit: 1, msg: []string{"no session matches"}},
	} {
		list := known
		if name == "no known sessions" {
			list = nil
		}
		id, msg, exit := resolveSessionID(tc.arg, list)
		if id != tc.id || exit != tc.exit {
			t.Errorf("%s: id %q exit %d, want %q %d (msg %q)", name, id, exit, tc.id, tc.exit, msg)
		}
		for _, m := range tc.msg {
			if !strings.Contains(msg, m) {
				t.Errorf("%s: message %q missing %q", name, msg, m)
			}
		}
	}
}
