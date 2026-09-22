package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Attention groups: the session-grouped operator queue. Computed ONCE here
// and served from /posture so the console, the menubar, and the fleet
// heartbeat all render the same queue — previously the console re-derived it
// in JS and the menubar kept a third predicate, and the three disagreed.

// AttentionItem is one actionable signal inside a group. Priority orders
// items inside the group (higher first): guard 5, resource 4, incident 3,
// flag 2, egress 1.
type AttentionItem struct {
	Kind      string                `json:"kind"` // resource | guard | incident | flag | egress
	Priority  int                   `json:"priority"`
	ID        string                `json:"id,omitempty"`
	Action    string                `json:"action,omitempty"`
	Title     string                `json:"title"`
	Detail    string                `json:"detail,omitempty"`
	Rule      string                `json:"rule,omitempty"`
	Path      string                `json:"path,omitempty"`
	ScopeText string                `json:"scopeText,omitempty"`
	Status    string                `json:"status,omitempty"`
	Count     int                   `json:"count,omitempty"`
	Hosts     []string              `json:"hosts,omitempty"`
	Advisor   *model.AdvisorVerdict `json:"advisor,omitempty"`
}

// AttentionGroup is one agent session (or an explicit unattributed bucket)
// with its pending decisions, worst first.
type AttentionGroup struct {
	Key          string          `json:"key"`
	Label        string          `json:"label"`
	Agent        string          `json:"agent"`
	Workspace    string          `json:"workspace,omitempty"`
	RootPID      int32           `json:"rootPid,omitempty"`
	PIDs         []int32         `json:"pids,omitempty"`
	RSSBytes     uint64          `json:"rssBytes,omitempty"`
	CPUPercent   float64         `json:"cpuPercent,omitempty"`
	ProcessCount int             `json:"processCount,omitempty"`
	Items        []AttentionItem `json:"items"`
}

// attentionSession is the internal grouping target: a live session a signal
// can be attributed to.
type attentionSession struct {
	key          string
	agent        string
	workspace    string
	label        string
	rootPID      int32
	pids         []int32
	rssBytes     uint64
	cpuPercent   float64
	processCount int
	diagnoses    []resource.Diagnosis
	control      *resource.SessionControl
}

// computeAttentionGroups builds the session-grouped queue. Signals without a
// PID (guard prompts, uninspected egress) join a live session only when the
// agent name identifies exactly one; ambiguous work stays in an explicit
// agent-level group rather than being guessed onto a process.
func (a *API) computeAttentionGroups(st Status) []AttentionGroup {
	var sessions []attentionSession
	if a.resources != nil {
		for _, s := range a.resources().Sessions {
			sess := attentionSession{
				key:          firstNonEmpty([]string{s.Key, fmt.Sprint(s.RootPID)}),
				agent:        s.Name,
				workspace:    s.Workspace,
				label:        firstNonEmpty([]string{cwdBase(s.Workspace), familyTitle(s.Name)}),
				rootPID:      s.RootPID,
				rssBytes:     s.RSSBytes,
				cpuPercent:   s.CPUPercent,
				processCount: s.ProcessCount,
				diagnoses:    s.Diagnoses,
				control:      s.Control,
			}
			for _, p := range s.Processes {
				sess.pids = append(sess.pids, p.PID)
			}
			if sess.processCount == 0 {
				sess.processCount = len(sess.pids)
			}
			sessions = append(sessions, sess)
		}
	}
	if len(sessions) == 0 {
		// Fallback: no resource tracker — group by the process trees.
		for _, t := range st.Trees {
			sess := attentionSession{
				key:          fmt.Sprint(firstPID(t.Root.RootPID, t.Root.PID)),
				agent:        t.Root.Name,
				workspace:    t.Root.CWD,
				label:        firstNonEmpty([]string{cwdBase(t.Root.CWD), familyTitle(t.Root.Name)}),
				rootPID:      t.Root.PID,
				rssBytes:     t.RSSBytes,
				processCount: 1 + len(t.Children),
			}
			for _, c := range t.Children {
				sess.pids = append(sess.pids, c.PID)
			}
			sessions = append(sessions, sess)
		}
	}

	byPID := map[int32]*attentionSession{}
	byAgent := map[string][]*attentionSession{}
	for i := range sessions {
		s := &sessions[i]
		for _, pid := range s.pids {
			byPID[pid] = s
		}
		if s.rootPID != 0 {
			byPID[s.rootPID] = s
		}
		if k := strings.ToLower(s.agent); k != "" {
			byAgent[k] = append(byAgent[k], s)
		}
	}

	groups := map[string]*AttentionGroup{}
	groupFor := func(agent string, pid int32) *AttentionGroup {
		var sess *attentionSession
		if direct, ok := byPID[pid]; ok {
			sess = direct
		} else if matches := byAgent[strings.ToLower(agent)]; len(matches) == 1 {
			sess = matches[0]
		}
		var key string
		if sess != nil {
			key = "session:" + sess.key
		} else {
			key = "agent:" + firstNonEmpty([]string{agent, "unattributed"})
		}
		g, ok := groups[key]
		if !ok {
			g = &AttentionGroup{Key: key, Items: []AttentionItem{}}
			if sess != nil {
				g.Label = sess.label
				g.Agent = sess.agent
				g.Workspace = sess.workspace
				g.RootPID = sess.rootPID
				g.PIDs = sess.pids
				g.RSSBytes = sess.rssBytes
				g.CPUPercent = sess.cpuPercent
				g.ProcessCount = sess.processCount
			} else {
				g.Label = firstNonEmpty([]string{agent, "Unattributed"}) + " activity"
				g.Agent = firstNonEmpty([]string{agent, "unknown"})
			}
			groups[key] = g
		}
		return g
	}
	add := func(agent string, pid int32, item AttentionItem) {
		g := groupFor(agent, pid)
		g.Items = append(g.Items, item)
	}

	// Resource pressure: sessions with a pending intervention decision.
	for i := range sessions {
		s := &sessions[i]
		if s.control == nil || s.control.PendingID == "" {
			continue
		}
		detail := "This session exceeded its configured resource budget."
		if len(s.diagnoses) > 0 && s.diagnoses[0].Summary != "" {
			detail = s.diagnoses[0].Summary
		}
		add(s.agent, s.rootPID, AttentionItem{
			Kind: "resource", Priority: 4, ID: s.control.PendingID,
			Action: string(s.control.NextAction),
			Title:  "Resource pressure", Detail: detail,
		})
		if s.control.NextAction == "" {
			g := groupFor(s.agent, s.rootPID)
			g.Items[len(g.Items)-1].Action = "intervention"
		}
	}

	// Guard prompts waiting on the operator.
	if a.guardBroker != nil {
		for _, p := range a.guardBroker.Pending() {
			tool := firstNonEmpty([]string{p.Tool, "Tool"})
			path := firstNonEmpty([]string{p.Path, "a protected path"})
			add(p.Agent, 0, AttentionItem{
				Kind: "guard", Priority: 5, ID: p.ID,
				Title:  "Guard decision",
				Detail: tool + " wants access to " + path,
				Rule:   p.RuleID, Path: p.Path,
				ScopeText: p.ScopeText, Advisor: p.Advisor,
			})
		}
	}

	// Critical/high incidents not yet resolved.
	for _, inc := range a.store.RecentIncidents(25) {
		wf, _ := a.store.IncidentStatus(inc.ID)
		status := wf.Status
		if status == "" {
			status = "open"
		}
		if status == "resolved" || (inc.Risk != model.RiskCritical && inc.Risk != model.RiskHigh) {
			continue
		}
		detail := firstNonEmpty([]string{inc.Summary, inc.Rule, "A security incident needs review."})
		add(inc.Agent, inc.PID, AttentionItem{
			Kind: "incident", Priority: 3, ID: inc.ID,
			Title: "Critical incident", Detail: detail, Status: status,
		})
	}

	// Unacknowledged critical flags.
	for _, f := range a.store.QueryFlags(store.FlagFilter{MinSeverity: 3, Limit: 50, Unacted: true}) {
		detail := f.Rule
		if len(f.Evidence) > 0 {
			detail = f.Rule + " — " + f.Evidence[0].String()
		}
		add(f.Agent, f.PID, AttentionItem{
			Kind: "flag", Priority: 2, ID: f.ID,
			Title: "Critical finding", Detail: detail,
		})
	}

	// Uninspected egress, one item per group with host rollup.
	if a.correlator != nil {
		for _, row := range a.correlator.UninspectedEgressSummarySince(time.Now().Add(-24 * time.Hour)) {
			g := groupFor(row.Agent, 0)
			var item *AttentionItem
			for i := range g.Items {
				if g.Items[i].Kind == "egress" {
					item = &g.Items[i]
					break
				}
			}
			if item == nil {
				g.Items = append(g.Items, AttentionItem{Kind: "egress", Priority: 1, Title: "Uninspected egress", Hosts: []string{}})
				item = &g.Items[len(g.Items)-1]
			}
			item.Count += row.Count
			if row.Host != "" && !containsString(item.Hosts, row.Host) {
				item.Hosts = append(item.Hosts, row.Host)
			}
			item.Detail = fmt.Sprintf("%d connection%s across %d endpoint%s bypassed inspection.",
				item.Count, plural(item.Count), len(item.Hosts), plural(len(item.Hosts)))
		}
	}

	out := make([]AttentionGroup, 0, len(groups))
	for _, g := range groups {
		if len(g.Items) == 0 {
			continue
		}
		sort.SliceStable(g.Items, func(i, j int) bool { return g.Items[i].Priority > g.Items[j].Priority })
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := out[i].Items[0].Priority, out[j].Items[0].Priority
		if pi != pj {
			return pi > pj
		}
		if len(out[i].Items) != len(out[j].Items) {
			return len(out[i].Items) > len(out[j].Items)
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func cwdBase(cwd string) string {
	s := strings.TrimRight(cwd, "/")
	if s == "" {
		return ""
	}
	if i := strings.LastIndexAny(s, "/\\"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func familyTitle(name string) string {
	if name == "" {
		return "Unknown"
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func firstPID(values ...int32) int32 {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
