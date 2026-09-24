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

// wtRow, wtRepo and wtReport mirror the daemon's GET /worktrees body.
type wtRow struct {
	Path     string   `json:"path"`
	Branch   string   `json:"branch"`
	Detached bool     `json:"detached"`
	State    string   `json:"state"`
	Reasons  []string `json:"reasons"`
	Stale    bool     `json:"stale"`
	IdleDays int      `json:"idle_days"`
	// LastActivity is absent when nothing dates the worktree (its
	// directory is gone); the table prints "-" instead of 0 days.
	LastActivity string `json:"last_activity"`
	InUse        bool   `json:"in_use"`
	SizeBytes    int64  `json:"size_bytes"`
	SizePartial  bool   `json:"size_partial"`
}

type wtRepo struct {
	Path          string  `json:"path"`
	Source        string  `json:"source"`
	DefaultBranch string  `json:"default_branch"`
	SizeBytes     int64   `json:"size_bytes"`
	Worktrees     []wtRow `json:"worktrees"`
}

type wtReport struct {
	DurationMS int64 `json:"duration_ms"`
	Cached     bool  `json:"cached"`
	StaleDays  int   `json:"stale_days"`
	Summary    struct {
		Repos     int `json:"repos"`
		Worktrees int `json:"worktrees"`
		Remove    int `json:"remove"`
		Review    int `json:"review"`
		Keep      int `json:"keep"`
		Prune     int `json:"prune"`
		Stale     int `json:"stale"`
		// Sizes are lower bounds while Sizing.
		SizeBytes      int64 `json:"size_bytes"`
		RemovableBytes int64 `json:"removable_bytes"`
	} `json:"summary"`
	Sizing  bool `json:"sizing"`
	Volumes []struct {
		Mount      string `json:"mount"`
		TotalBytes uint64 `json:"total_bytes"`
		FreeBytes  uint64 `json:"free_bytes"`
	} `json:"volumes"`
	Reclaimed *wtTotals `json:"reclaimed"`
	Repos     []wtRepo  `json:"repos"`
	Errors    []string  `json:"errors"`
	// Advice is the local advisor's note per worktree path.
	Advice map[string]wtNote `json:"advice"`
}

// wtTotals mirrors the cleanup ledger totals.
type wtTotals struct {
	Bytes        int64 `json:"bytes"`
	Count        int   `json:"count"`
	Bytes30d     int64 `json:"bytes_30d"`
	Count30d     int   `json:"count_30d"`
	TrashedBytes int64 `json:"trashed_bytes"`
	TrashedCount int   `json:"trashed_count"`
}

type wtNote struct {
	Assessment string  `json:"assessment"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

// wtScanTimeout covers a full scan: the daemon bounds one at 3 minutes.
const wtScanTimeout = 200 * time.Second

func handleWorktrees(client *http.Client) {
	c := *client
	c.Timeout = wtScanTimeout
	if err := runWorktrees(os.Stdout, &c, os.Args[2:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runWorktrees dispatches `worktrees [add|hide|remove|prune <path>]` and
// the list view.
func runWorktrees(w io.Writer, client *http.Client, args []string) error {
	if len(args) > 0 && (args[0] == "remove" || args[0] == "prune") {
		return runWorktreeRemove(w, client, args)
	}
	if len(args) > 0 && args[0] == "advise" {
		return runWorktreeAdvise(w, client, args)
	}
	if len(args) > 0 && (args[0] == "add" || args[0] == "hide") {
		if len(args) < 2 {
			return fmt.Errorf("usage: secure-agent worktrees %s <path>", args[0])
		}
		abs, err := filepath.Abs(args[1])
		if err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]any{"path": abs, "hidden": args[0] == "hide"})
		code, resp := request(client, http.MethodPost, "http://unix/worktrees/repos", string(body))
		if code == http.StatusForbidden {
			return errWorktreeForbidden(args[0])
		}
		if code != 200 {
			return fmt.Errorf("worktrees %s failed (%d): %s", args[0], code, strings.TrimSpace(resp))
		}
		var out struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal([]byte(resp), &out)
		if args[0] == "add" {
			fmt.Fprintf(w, "added %s\n", out.Path)
		} else {
			fmt.Fprintf(w, "hid %s\n", abs)
		}
		return nil
	}

	path := "http://unix/worktrees"
	if slices.Contains(args, "--refresh") {
		path += "?refresh=1"
	}
	code, body := request(client, http.MethodGet, path, "")
	if code != 200 {
		return fmt.Errorf("worktrees failed (%d): %s", code, strings.TrimSpace(body))
	}
	if slices.Contains(args, "--json") {
		fmt.Fprintln(w, body)
		return nil
	}
	var rep wtReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		return fmt.Errorf("worktrees: unreadable response: %v", err)
	}
	f := wtFilter{
		State: queryFlag(args, "--state", ""),
		Repo:  queryFlag(args, "--repo", ""),
		Stale: slices.Contains(args, "--stale"),
	}
	home, _ := os.UserHomeDir()
	fmt.Fprint(w, formatWorktrees(rep, f, home))
	return nil
}

// runWorktreeRemove removes one worktree or prunes a repository's missing
// ones. A refusal prints the fresh verdict and fails.
func runWorktreeRemove(w io.Writer, client *http.Client, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: secure-agent worktrees %s <path>", args[0])
	}
	abs, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	req := map[string]any{"path": abs}
	if args[0] == "prune" {
		req = map[string]any{"repo": abs, "prune": true}
	}
	body, _ := json.Marshal(req)
	code, resp := request(client, http.MethodPost, "http://unix/worktrees/remove", string(body))
	var out struct {
		Removed string   `json:"removed"`
		Bytes   int64    `json:"bytes"`
		Branch  string   `json:"branch"`
		Pruned  []string `json:"pruned"`
		State   string   `json:"state"`
		Reasons []string `json:"reasons"`
	}
	_ = json.Unmarshal([]byte(resp), &out)
	switch {
	case code == http.StatusForbidden:
		return errWorktreeForbidden(args[0])
	case code == http.StatusConflict && out.State != "":
		return fmt.Errorf("not removed: %s is %s\n  %s", abs, out.State, strings.Join(out.Reasons, "\n  "))
	case code != 200:
		return fmt.Errorf("worktrees %s failed (%d): %s", args[0], code, strings.TrimSpace(resp))
	case args[0] == "prune":
		for _, p := range out.Pruned {
			fmt.Fprintf(w, "pruned %s\n", p)
		}
	default:
		fmt.Fprintf(w, "removed %s", out.Removed)
		if out.Bytes > 0 {
			fmt.Fprintf(w, " — %s reclaimed", humanBytes(out.Bytes))
		}
		if out.Branch != "" {
			fmt.Fprintf(w, " (branch %s kept)", out.Branch)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// runWorktreeAdvise asks the local advisor for a note on one worktree.
func runWorktreeAdvise(w io.Writer, client *http.Client, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: secure-agent worktrees advise <path>")
	}
	abs, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"path": abs})
	code, resp := request(client, http.MethodPost, "http://unix/worktrees/advise", string(body))
	switch {
	case code == http.StatusForbidden:
		return errWorktreeForbidden("advise")
	case code != 200:
		return fmt.Errorf("worktrees advise failed (%d): %s", code, strings.TrimSpace(resp))
	}
	var out struct {
		Queued bool `json:"queued"`
	}
	_ = json.Unmarshal([]byte(resp), &out)
	if !out.Queued {
		return fmt.Errorf("not queued: the advisor is off or its queue is full")
	}
	fmt.Fprintf(w, "asked the advisor about %s; the note shows under the row in `secure-agent worktrees` once the local model answers\n", abs)
	return nil
}

// errWorktreeForbidden explains a 403 on a worktree change: while the menu
// bar app runs, only it (and its console) may change state, and an agent
// session never may.
func errWorktreeForbidden(verb string) error {
	return fmt.Errorf("worktrees %s refused (403): while the menu bar app runs, changes go through it — use the console's Worktrees tab; agent sessions cannot make changes", verb)
}

type wtFilter struct {
	State string
	Repo  string
	Stale bool
}

func (f wtFilter) keep(repo string, r wtRow) bool {
	if r.State == "main" {
		return false
	}
	if f.State != "" && r.State != f.State {
		return false
	}
	if f.Repo != "" && !strings.Contains(repo, f.Repo) {
		return false
	}
	return !f.Stale || r.Stale
}

// formatWorktrees prints one block per repository with matching non-main
// rows, then the summary line and the scan's errors.
func formatWorktrees(rep wtReport, f wtFilter, home string) string {
	var b strings.Builder
	// Biggest projects first: the list is where to reclaim disk.
	repos := append([]wtRepo(nil), rep.Repos...)
	sort.SliceStable(repos, func(i, j int) bool { return repos[i].SizeBytes > repos[j].SizeBytes })
	for _, repo := range repos {
		var rows []wtRow
		for _, r := range repo.Worktrees {
			if f.keep(repo.Path, r) {
				rows = append(rows, r)
			}
		}
		if len(rows) == 0 {
			continue
		}
		meta := []string{}
		if repo.DefaultBranch != "" {
			meta = append(meta, repo.DefaultBranch)
		}
		if repo.Source != "" {
			meta = append(meta, repo.Source)
		}
		fmt.Fprintf(&b, "%s", tildePath(repo.Path, home))
		if len(meta) > 0 {
			fmt.Fprintf(&b, "  (%s)", strings.Join(meta, ", "))
		}
		if repo.SizeBytes > 0 {
			fmt.Fprintf(&b, " · %s", humanBytes(repo.SizeBytes))
		}
		b.WriteString("\n")
		for _, r := range rows {
			stale := ""
			if r.Stale {
				stale = "stale"
			}
			branch := r.Branch
			if branch == "" && r.Detached {
				branch = "(detached)"
			}
			idle := "-"
			if r.LastActivity != "" {
				idle = fmt.Sprintf("%dd", r.IdleDays)
			}
			size := "-"
			if r.SizeBytes > 0 {
				size = humanBytes(r.SizeBytes)
				if r.SizePartial {
					size = "≥" + size
				}
			}
			fmt.Fprintf(&b, "  %-6s  %-5s  %5s  %9s  %-32s  %s\n", r.State, stale, idle, size, clip(branch, 32), relPath(r.Path, repo.Path, home))
			for _, reason := range r.Reasons {
				fmt.Fprintf(&b, "          %s\n", reason)
			}
			if n, ok := rep.Advice[r.Path]; ok {
				fmt.Fprintf(&b, "          advisor: %s (%.0f%%) — %s\n", n.Assessment, n.Confidence*100, n.Rationale)
			}
		}
	}
	s := rep.Summary
	fmt.Fprintf(&b, "%s · %s · %d remove · %d review · %d keep · %d prune · %d stale (idle > %dd)",
		plural(s.Repos, "repo", "repos"), plural(s.Worktrees, "worktree", "worktrees"), s.Remove, s.Review, s.Keep, s.Prune, s.Stale, rep.StaleDays)
	if rep.Cached {
		b.WriteString(" · cached, --refresh rescans")
	} else {
		fmt.Fprintf(&b, " · scan %.1fs", float64(rep.DurationMS)/1000)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "worktrees use %s; %s in state remove", humanBytes(s.SizeBytes), humanBytes(s.RemovableBytes))
	if rep.Sizing {
		b.WriteString(" (still measuring: lower bounds)")
	}
	b.WriteString("\n")
	for _, v := range rep.Volumes {
		fmt.Fprintf(&b, "disk %s: %s free of %s\n", v.Mount, humanBytes(int64(v.FreeBytes)), humanBytes(int64(v.TotalBytes)))
	}
	if t := rep.Reclaimed; t != nil && t.Count > 0 {
		fmt.Fprintf(&b, "reclaimed %s over %s (%s in the last 30 days)\n", humanBytes(t.Bytes), plural(t.Count, "cleanup", "cleanups"), humanBytes(t.Bytes30d))
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(&b, "error: %s\n", e)
	}
	return b.String()
}

// humanBytes renders a byte count in 1024 units: 512 B, 1.5 KB, 3.2 GB.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// relPath shows a worktree inside its repository relative to it, and any
// other path under the home directory with ~.
func relPath(p, repo, home string) string {
	if rel, ok := strings.CutPrefix(p, strings.TrimSuffix(repo, "/")+"/"); ok {
		return rel
	}
	return tildePath(p, home)
}

func tildePath(p, home string) string {
	if home != "" {
		if rest, ok := strings.CutPrefix(p, strings.TrimSuffix(home, "/")+"/"); ok {
			return "~/" + rest
		}
	}
	return p
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
