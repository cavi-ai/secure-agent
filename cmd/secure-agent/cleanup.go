package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
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

func handleCleanup(client *http.Client) {
	if err := runCleanup(os.Stdout, client, os.Args[2:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runCleanup: `cleanup log [--limit N] [--json]` prints the ledger.
func runCleanup(w io.Writer, client *http.Client, args []string) error {
	if len(args) == 0 || args[0] != "log" {
		return fmt.Errorf("usage: secure-agent cleanup log [--limit N] [--json]")
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
