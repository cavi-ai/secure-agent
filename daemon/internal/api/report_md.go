package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

const (
	mdFilesShown    = 25
	mdTimelineShown = 100
)

// renderSessionMarkdown renders a SessionReport as markdown for a PR body or
// a ticket: a title line, a summary, then one section per list. Empty
// sections read "none". Times are daemon-local.
func renderSessionMarkdown(rep store.SessionReport) string {
	var b strings.Builder
	sess := rep.Session
	where := sess.Repo
	switch {
	case where != "" && sess.Branch != "":
		where += "@" + sess.Branch
	case where == "":
		where = sess.Workspace
	}
	if where == "" {
		where = "(no workspace)"
	}
	ended := "live"
	if sess.EndedAt != nil {
		ended = sess.EndedAt.Local().Format("2006-01-02 15:04")
		if sess.EndedAt.Local().Format("2006-01-02") == sess.StartedAt.Local().Format("2006-01-02") {
			ended = sess.EndedAt.Local().Format("15:04")
		}
	}
	fmt.Fprintf(&b, "# %s · %s — %s → %s (%s)\n", mdText(orDash(sess.Harness)), mdText(where),
		sess.StartedAt.Local().Format("2006-01-02 15:04"), ended, fmtSeconds(rep.DurationS))
	fmt.Fprintf(&b, "Session %s · %s · identity: %s\n", mdCode(sess.ID), mdText(orDash(sess.Status)), mdText(orDash(sess.Confidence)))

	toolErrors := 0
	for _, t := range rep.Tools {
		toolErrors += t.Errors
	}
	b.WriteString("\n## Summary\n")
	fmt.Fprintf(&b, "- Turns %d · tool calls %d (%d errors) · model calls %d · tokens %d in / %d out · cost %s",
		rep.Turns, rep.ToolCalls, toolErrors, rep.ModelCalls, rep.TokensIn, rep.TokensOut, fmtUSD(rep.CostUSD))
	if rep.Unpriced > 0 {
		fmt.Fprintf(&b, " (%d unpriced)", rep.Unpriced)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- Files touched %s · hosts contacted %s · guard decisions %d · findings %d · secret hits %d\n",
		countOrMore(len(rep.Files), store.ReportTopN), countOrMore(len(rep.Hosts), store.ReportTopN),
		len(rep.Guard), len(rep.Flags), len(rep.SecretHits))

	b.WriteString("\n## Models\n")
	if len(rep.Models) == 0 {
		b.WriteString("none\n")
	} else {
		b.WriteString("| model | calls | tokens in | tokens out | cost |\n|---|---:|---:|---:|---:|\n")
		for _, m := range rep.Models {
			cost := fmtUSD(m.CostUSD)
			switch {
			case m.Unpriced == m.Calls:
				cost = "unpriced"
			case m.Unpriced > 0:
				cost += fmt.Sprintf(" (%d unpriced)", m.Unpriced)
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", mdCell(m.Model), m.Calls, m.TokensIn, m.TokensOut, cost)
		}
	}

	b.WriteString("\n## Tools\n")
	if len(rep.Tools) == 0 {
		b.WriteString("none\n")
	} else {
		b.WriteString("| tool | calls | errors | time |\n|---|---:|---:|---:|\n")
		for _, t := range rep.Tools {
			fmt.Fprintf(&b, "| %s | %d | %d | %s |\n", mdCell(t.Key), t.Count, t.Errors, fmtMs(t.DurationMs))
		}
	}

	b.WriteString("\n## Files touched\n")
	writeCounts(&b, rep.Files, mdFilesShown, true)
	b.WriteString("\n## Network\n")
	writeCounts(&b, rep.Hosts, len(rep.Hosts), false)

	b.WriteString("\n## Guard decisions\n")
	if len(rep.Guard) == 0 {
		b.WriteString("none\n")
	}
	for _, g := range rep.Guard {
		fmt.Fprintf(&b, "- %s %s %s\n", clock(g.TS), g.Kind, mdText(g.Label))
	}

	b.WriteString("\n## Findings\n")
	if len(rep.Flags) == 0 {
		b.WriteString("none\n")
	}
	for _, f := range rep.Flags {
		fmt.Fprintf(&b, "- severity %d · %s · %s\n", f.Severity, mdText(f.Rule), f.TS.Local().Format("2006-01-02 15:04:05"))
	}

	b.WriteString("\n## Secret hits\n")
	if len(rep.SecretHits) == 0 {
		b.WriteString("none\n")
	}
	for _, h := range rep.SecretHits {
		fmt.Fprintf(&b, "- %s · %s · %s\n", mdText(h.Label), mdText(orDash(h.Status)), clock(h.TS))
	}

	b.WriteString("\n## Timeline\n")
	if len(rep.Timeline) == 0 {
		b.WriteString("none\n")
	}
	shown := min(len(rep.Timeline), mdTimelineShown)
	for _, l := range rep.Timeline[:shown] {
		parts := []string{"-", clock(l.TS), l.Kind}
		if l.Label != "" {
			parts = append(parts, mdText(l.Label))
		}
		if l.Status != "" {
			parts = append(parts, mdText(l.Status))
		}
		if l.DurationMs > 0 {
			parts = append(parts, fmtMs(l.DurationMs))
		}
		b.WriteString(strings.Join(parts, " ") + "\n")
	}
	if more := rep.Events - shown; more > 0 {
		fmt.Fprintf(&b, "- … %d more\n", more)
	}
	return b.String()
}

// writeCounts renders a "- key × count" list of at most n rows, then a
// "… N more" line; code wraps keys (paths) in backticks.
func writeCounts(b *strings.Builder, rows []store.ReportCount, n int, code bool) {
	if len(rows) == 0 {
		b.WriteString("none\n")
		return
	}
	shown := min(len(rows), n)
	for _, r := range rows[:shown] {
		key := mdText(r.Key)
		if code {
			key = mdCode(r.Key)
		}
		fmt.Fprintf(b, "- %s × %d\n", key, r.Count)
	}
	if more := len(rows) - shown; more > 0 {
		fmt.Fprintf(b, "- … %d more\n", more)
	}
}

// fmtUSD renders dollars with two decimals and thousands separators; a
// non-zero amount under a cent reads "<$0.01" (the console's fmtUSD rule).
func fmtUSD(v float64) string {
	if v > 0 && v < 0.01 {
		return "<$0.01"
	}
	s := strconv.FormatFloat(v, 'f', 2, 64)
	whole, frac, _ := strings.Cut(s, ".")
	var g strings.Builder
	for i, c := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			g.WriteByte(',')
		}
		g.WriteRune(c)
	}
	return "$" + g.String() + "." + frac
}

// fmtSeconds renders a duration as "45s", "12m 5s" or "2h 3m".
func fmtSeconds(s int64) string {
	switch {
	case s <= 0:
		return "0s"
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm %ds", s/60, s%60)
	default:
		return fmt.Sprintf("%dh %dm", s/3600, s%3600/60)
	}
}

// fmtMs renders a call duration as "850ms", "1.5s" or a fmtSeconds value.
func fmtMs(ms int64) string {
	switch {
	case ms < 1000:
		return fmt.Sprintf("%dms", ms)
	case ms < 60000:
		return strconv.FormatFloat(float64(ms)/1000, 'f', 1, 64) + "s"
	default:
		return fmtSeconds(ms / 1000)
	}
}

// clock renders an RFC3339 stamp as local HH:MM:SS.
func clock(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Local().Format("15:04:05")
}

func countOrMore(n, limit int) string {
	if n >= limit {
		return strconv.Itoa(limit) + "+"
	}
	return strconv.Itoa(n)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// mdText flattens line breaks so a value cannot start a new markdown block.
func mdText(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// mdCell is mdText with table pipes escaped.
func mdCell(s string) string {
	return strings.ReplaceAll(mdText(s), "|", `\|`)
}

// mdCode wraps s in a code span, widening the fence when s holds a backtick.
func mdCode(s string) string {
	s = mdText(s)
	if strings.Contains(s, "`") {
		return "`` " + s + " ``"
	}
	return "`" + s + "`"
}
