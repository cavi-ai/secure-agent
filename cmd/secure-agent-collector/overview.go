package main

// The overview page: one dark HTML card per node — posture dot, counts, last
// incident, staleness warning. Plain fmt.Fprintf templates; no assets, no JS.

import (
	"fmt"
	"html"
	"net/http"
	"time"
)

// staleAfter is how long a node can go silent before the overview flags it.
// Nodes emit at least a guard decision or flag every session; a quiet node
// might genuinely be idle, but the operator should know.
const staleAfter = 10 * time.Minute

func (c *Collector) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	nodes := c.store.Rollup()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8">
<title>secure-agent fleet</title>
<style>
  body { background:#0d1117; color:#e6edf3; font:14px/1.5 -apple-system,system-ui,sans-serif; margin:0; padding:32px; }
  h1 { font-size:18px; margin:0 0 4px; } .sub { color:#8b949e; margin:0 0 24px; font-size:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:14px; }
  .card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:14px 16px; }
  .head { display:flex; align-items:center; gap:9px; margin-bottom:10px; }
  .dot { width:9px; height:9px; border-radius:50%; background:#3fb950; box-shadow:0 0 7px #3fb950; }
  .dot.stale { background:#d29922; box-shadow:0 0 7px #d29922; }
  .dot.gone { background:#f85149; box-shadow:0 0 9px #f85149; }
  .id { font-weight:600; font-family:ui-monospace,monospace; font-size:13px; }
  .ver { color:#8b949e; font-size:11px; margin-left:auto; font-family:ui-monospace,monospace; }
  .row { display:flex; justify-content:space-between; color:#8b949e; font-size:12.5px; padding:2.5px 0; }
  .row b { color:#e6edf3; font-weight:600; }
  .latest { color:#8b949e; font-size:12px; border-top:1px solid #21262d; margin-top:9px; padding-top:8px; min-height:16px; }
  .warn { color:#d29922; font-size:12px; margin-top:7px; }
  .empty { color:#8b949e; }
  @media (prefers-color-scheme: light) {
    body { background:#f6f8fa; color:#1f2328; } .card { background:#fff; border-color:#d0d7de; }
    .row,.sub,.latest,.ver { color:#656d76; } .latest { border-color:#d0d7de; }
  }
</style></head><body>
<h1>secure-agent fleet</h1>
<p class="sub">Reference collector — node rollup. `)

	totalFlags, totalIncidents := 0, 0
	now := time.Now()
	if len(nodes) == 0 {
		fmt.Fprint(w, `<div class="empty">No nodes have reported yet — point a node's <code>fleet.webhooks</code> at this collector.</div>`)
	}
	for _, st := range nodes {
		totalFlags += st.Flags
		totalIncidents += st.Incidents
		stateNote := ""
		switch {
		case now.Sub(st.LastSeen) > 2*staleAfter:
			stateNote = "gone quiet"
		case now.Sub(st.LastSeen) > staleAfter:
			stateNote = "stale"
		}
		dotClass := ""
		if stateNote == "gone quiet" {
			dotClass = "gone"
		} else if stateNote == "stale" {
			dotClass = "stale"
		}
		fmt.Fprintf(w, `<div class="card"><div class="head"><span class="dot %s"></span><span class="id">%s</span><span class="ver">%s</span></div>
<div class="row"><span>Flags</span><b>%d</b></div>
<div class="row"><span>Incidents</span><b>%d</b></div>
<div class="row"><span>Guard decisions</span><b>%d</b></div>
<div class="row"><span>Last seen</span><b>%s</b></div>
<div class="latest">%s</div>
%s</div>`,
			dotClass, html.EscapeString(st.NodeID), html.EscapeString(st.Version),
			st.Flags, st.Incidents, st.GuardDecisions,
			html.EscapeString(st.LastSeen.Format("15:04:05 MST")),
			html.EscapeString(orDash(st.LatestIncident, st.LatestFlag)),
			stalenessLine(stateNote, st.LastSeen))
	}
	fmt.Fprintf(w, `<p class="sub" style="margin-top:22px">Totals: %d flag(s), %d incident(s) across %d node(s).</p></body></html>`,
		totalFlags, totalIncidents, len(nodes))
}

func orDash(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

// stalenessLine renders the warning paragraph when a node is stale or gone.
func stalenessLine(stateNote string, lastSeen time.Time) string {
	if stateNote == "" {
		return ""
	}
	return fmt.Sprintf(`<div class="warn">⚠ %s — last report %s ago</div>`,
		html.EscapeString(stateNote), html.EscapeString(time.Since(lastSeen).Round(time.Second).String()))
}
