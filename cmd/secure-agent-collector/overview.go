package main

// The overview page: a fleet headline ("2 critical · 1 stale · 12 all-clear")
// over one dark HTML card per node — hostname, posture chip, windowed counts,
// liveness. Plain fmt.Fprintf templates; no assets, no JS.

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

// fleetHeadline is the one-glance fleet answer, counted from posture state
// and liveness — the same shape as the daemon's posture banner.
type fleetHeadline struct {
	critical, attention, stale, allClear, legacy int
}

func (h fleetHeadline) total() int {
	return h.critical + h.attention + h.stale + h.allClear + h.legacy
}

func summarizeFleet(nodes []*NodeState, now time.Time) fleetHeadline {
	var h fleetHeadline
	for _, st := range nodes {
		switch {
		case st.PostureState == "critical":
			h.critical++
		case st.PostureState == "attention":
			h.attention++
		case livenessState(st, now) != "":
			h.stale++
		case st.HasStatus:
			h.allClear++
		default:
			h.legacy++
		}
	}
	return h
}

func (h fleetHeadline) html() string {
	parts := []string{}
	if h.critical > 0 {
		parts = append(parts, fmt.Sprintf(`<b class="crit">%d critical</b>`, h.critical))
	}
	if h.attention > 0 {
		parts = append(parts, fmt.Sprintf(`<b class="att">%d need attention</b>`, h.attention))
	}
	if h.stale > 0 {
		parts = append(parts, fmt.Sprintf(`<b class="att">%d stale</b>`, h.stale))
	}
	if h.allClear > 0 {
		parts = append(parts, fmt.Sprintf(`<b class="ok">%d all-clear</b>`, h.allClear))
	}
	if h.legacy > 0 {
		parts = append(parts, fmt.Sprintf(`%d legacy`, h.legacy))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ` · `)
}

// postureChip renders the node's own posture state as a colored pill.
func postureChip(state string) string {
	switch state {
	case "critical":
		return `<span class="chip crit">CRITICAL</span>`
	case "attention":
		return `<span class="chip att">ATTENTION</span>`
	case "all-clear":
		return `<span class="chip ok">ALL CLEAR</span>`
	default:
		return `<span class="chip legacy">LEGACY</span>`
	}
}

func labelChips(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	// stable order for stable rendering
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, `<span class="label">%s=%s</span>`, html.EscapeString(k), html.EscapeString(labels[k]))
	}
	return b.String()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

func relTime(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return now.Sub(t).Round(time.Second).String() + " ago"
}

func (c *Collector) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	nodes := c.store.Rollup()
	now := time.Now()
	head := summarizeFleet(nodes, now)
	rules := c.store.RuleAggregates()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8">
<title>secure-agent fleet</title>
<style>
  body { background:#0d1117; color:#e6edf3; font:14px/1.5 -apple-system,system-ui,sans-serif; margin:0; padding:32px; }
  h1 { font-size:18px; margin:0 0 4px; } .sub { color:#8b949e; margin:0 0 24px; font-size:12px; }
  .headline { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:12px 16px; margin-bottom:18px; font-size:14px; }
  .rules { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:12px 16px; margin-bottom:18px; }
  .rules h2 { font-size:13px; margin:0 0 8px; color:#8b949e; font-weight:600; }
  .rule-row { display:flex; justify-content:space-between; gap:12px; font-size:12.5px; padding:3px 0; }
  .rule-name { font-family:ui-monospace,monospace; color:#e6edf3; }
  .rule-stat { color:#8b949e; white-space:nowrap; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:14px; }
  .card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:14px 16px; }
  .card.crit { border-color:#f85149; }
  .head { display:flex; align-items:center; gap:9px; margin-bottom:4px; }
  .dot { width:9px; height:9px; border-radius:50%; background:#3fb950; box-shadow:0 0 7px #3fb950; }
  .dot.stale { background:#d29922; box-shadow:0 0 7px #d29922; }
  .dot.gone { background:#f85149; box-shadow:0 0 9px #f85149; }
  .name { font-weight:600; font-size:14px; }
  .nodeid { color:#8b949e; font-family:ui-monospace,monospace; font-size:11px; }
  .ver { color:#8b949e; font-size:11px; margin-left:auto; font-family:ui-monospace,monospace; }
  .chip { display:inline-block; font-size:10.5px; font-weight:700; border-radius:8px; padding:1px 7px; letter-spacing:.4px; }
  .chip.crit { background:rgba(248,81,73,.15); color:#f85149; }
  .chip.att { background:rgba(210,153,34,.15); color:#d29922; }
  .chip.ok { background:rgba(63,185,80,.15); color:#3fb950; }
  .chip.legacy { background:rgba(139,148,158,.15); color:#8b949e; }
  b.crit { color:#f85149; } b.att { color:#d29922; } b.ok { color:#3fb950; }
  .label { display:inline-block; background:#21262d; color:#8b949e; border-radius:6px; padding:0 6px; font-size:10.5px; margin-right:4px; font-family:ui-monospace,monospace; }
  .summary { color:#c9d1d9; font-size:12.5px; margin:6px 0; min-height:16px; }
  .row { display:flex; justify-content:space-between; color:#8b949e; font-size:12.5px; padding:2.5px 0; }
  .row b { color:#e6edf3; font-weight:600; }
  .row b.hot { color:#f85149; }
  .latest { color:#8b949e; font-size:12px; border-top:1px solid #21262d; margin-top:9px; padding-top:8px; min-height:16px; }
  .warn { color:#d29922; font-size:12px; margin-top:7px; }
  .empty { color:#8b949e; }
  @media (prefers-color-scheme: light) {
    body { background:#f6f8fa; color:#1f2328; } .card,.headline { background:#fff; border-color:#d0d7de; }
    .row,.sub,.latest,.ver,.nodeid,.rule-stat { color:#656d76; } .latest { border-color:#d0d7de; } .summary { color:#1f2328; }
    .label { background:#eaeef2; color:#656d76; } .rules h2 { color:#656d76; } .rule-name { color:#1f2328; }
  }
</style></head><body>
<h1>secure-agent fleet</h1>
<p class="sub">Reference collector — node rollup. `)

	if len(nodes) == 0 {
		fmt.Fprint(w, `<div class="empty">No nodes have reported yet — point a node's <code>fleet.webhooks</code> at this collector.</div>`)
	} else {
		fmt.Fprintf(w, `<div class="headline">%s</div>`, head.html())
	}

	// Cross-node rule aggregation: "is the same thing firing everywhere?"
	// Spread (N/M nodes) is the signal — one node is an incident, five is a
	// bad release.
	if len(rules.Rules) > 0 {
		fmt.Fprint(w, `<div class="rules"><h2>Rules across the fleet (24h)</h2>`)
		for _, ra := range rules.Rules {
			crit := ""
			if ra.Critical24h > 0 {
				crit = fmt.Sprintf(` · <b class="crit">%d critical</b>`, ra.Critical24h)
			}
			fmt.Fprintf(w, `<div class="rule-row"><span class="rule-name">%s</span><span class="rule-stat">%d/%d nodes · %d flag(s)%s</span></div>`,
				html.EscapeString(ra.Rule), ra.Nodes, rules.TotalNodes, ra.Flags24h, crit)
		}
		fmt.Fprint(w, `</div>`)
	}

	totalFlags, totalIncidents := 0, 0
	for _, st := range nodes {
		totalFlags += st.Flags
		totalIncidents += st.Incidents

		live := livenessState(st, now)
		dotClass := ""
		if live == "gone" {
			dotClass = "gone"
		} else if live == "stale" {
			dotClass = "stale"
		}
		cardClass := ""
		if st.PostureState == "critical" {
			cardClass = "crit"
		}
		critClass := ""
		if st.CriticalFlags24h > 0 {
			critClass = "hot"
		}
		guardLine := fmt.Sprintf(`<div class="row"><span>Guard allow / deny</span><b>%d / %d</b></div>`, st.GuardAllows, st.GuardDenies)

		fmt.Fprintf(w, `<div class="card %s"><div class="head"><span class="dot %s"></span><span class="name">%s</span>%s<span class="ver">%s</span></div>
<div class="nodeid">%s %s</div>
<div class="summary">%s</div>
<div class="row"><span>Flags (24h)</span><b>%d</b></div>
<div class="row"><span>Critical flags (24h)</span><b class="%s">%d</b></div>
<div class="row"><span>Incidents (24h)</span><b>%d</b></div>
%s
<div class="row"><span>Agents</span><b>%d</b></div>
<div class="row"><span>Last seen</span><b>%s</b></div>
<div class="latest">%s</div>
%s</div>`,
			cardClass, dotClass,
			html.EscapeString(st.displayName()), postureChip(st.PostureState),
			html.EscapeString(st.Version),
			html.EscapeString(shortID(st.NodeID)), labelChips(st.Labels),
			html.EscapeString(orDash(st.PostureSummary, "—")),
			st.Flags24h, critClass, st.CriticalFlags24h, st.Incidents24h,
			guardLine, st.Agents,
			html.EscapeString(relTime(st.LastSeen, now)),
			html.EscapeString(orDash(st.LatestIncident, st.LatestFlag)),
			stalenessLine(live, st.LastSeen, now)+gapsLine(st.Gaps))
	}
	fmt.Fprintf(w, `<p class="sub" style="margin-top:22px">Lifetime totals: %d flag(s), %d incident(s) across %d node(s). Counts above are rolling 24h.</p></body></html>`,
		totalFlags, totalIncidents, len(nodes))
}

func orDash(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	if fallback != "" {
		return fallback
	}
	return "—"
}

// stalenessLine renders the warning paragraph when a node is stale or gone.
func stalenessLine(state string, lastSeen, now time.Time) string {
	if state == "" {
		return ""
	}
	note := "stale"
	if state == "gone" {
		note = "gone quiet"
	}
	return fmt.Sprintf(`<div class="warn">⚠ %s — last report %s ago</div>`,
		html.EscapeString(note), html.EscapeString(now.Sub(lastSeen).Round(time.Second).String()))
}

// gapsLine surfaces sequence-gap loss: the node stamped deliveries that
// never arrived (backlog drops, collector downtime). Best-effort delivery is
// fine; SILENT loss is not.
func gapsLine(gaps int) string {
	if gaps <= 0 {
		return ""
	}
	return fmt.Sprintf(`<div class="warn">⚠ %d deliverie(s) lost — sequence gaps detected</div>`, gaps)
}
