package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Attention queue: computed once here and served from /posture. Every signal
// that needs the operator is appended once as a headline item (Items) and
// once as an item in exactly one group, so needs_you, the console hero and
// the Attention tab count the same set.

// AttentionItem priorities (higher first): guard 5, resource 4, incident 3
// (1 for an aging incident below high risk), flag and pattern 2 (1 when
// likely benign or below critical), recurring egress 1.
type AttentionItem struct {
	Kind      string                `json:"kind"` // resource | guard | incident | flag | pattern | recurring_egress
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
	// Disposition is set on flag items (the same verdict /flags/{id}/explain
	// serves) and pattern items (the worst open flag's).
	Disposition *model.Disposition `json:"disposition,omitempty"`
}

// AttentionGroup is one agent session, an explicit unattributed bucket, or
// the machine group (Key "machine") for signals no agent owns, with its
// pending decisions, worst first.
type AttentionGroup struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Agent        string  `json:"agent"`
	Workspace    string  `json:"workspace,omitempty"`
	RootPID      int32   `json:"rootPid,omitempty"`
	PIDs         []int32 `json:"pids,omitempty"`
	RSSBytes     uint64  `json:"rssBytes,omitempty"`
	CPUPercent   float64 `json:"cpuPercent,omitempty"`
	ProcessCount int     `json:"processCount,omitempty"`
	// Summary, on an agent-level group (Key "agent:…"), names the processes
	// and sessions behind its findings and whether they still run.
	Summary string          `json:"summary,omitempty"`
	Items   []AttentionItem `json:"items"`
}

// machineGroupKey is retained for the machine-level coverage section.
const machineGroupKey = "machine"

// attentionSession: a live session a signal can be attributed to.
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

// attentionFlags is the one flag query behind the queue: unacknowledged
// flags of severity 2 or more raised in the last 24h.
func (a *API) attentionFlags() []model.Flag {
	var out []model.Flag
	for _, f := range a.store.QueryFlags(store.FlagFilter{MinSeverity: 2, Limit: 25, Unacted: true}) {
		if isRecent(f.TS, 24*time.Hour) {
			out = append(out, f)
		}
	}
	return out
}

// machineAttentionItems are the signals no agent owns: dead collectors, and
// while agents are active, silent collectors and missing hooks.
func (a *API) machineAttentionItems(st Status) []PostureItem {
	var items []PostureItem
	if st.BusDropping {
		items = append(items, PostureItem{Kind: "event_loss", ID: "event-bus", Severity: 2,
			Title:  "Telemetry was dropped",
			Detail: fmt.Sprintf("%d subscriber deliveries dropped since daemon start. Monitoring history may be incomplete.", st.BusDrops)})
	}
	if h := st.StorageHealth; h != nil && h.Failures > 0 {
		detail := fmt.Sprintf("%d evidence persistence attempts failed since daemon start. Monitoring history may be incomplete.", h.Failures)
		if len(h.Active) > 0 {
			detail += " Writes still failing: " + strings.Join(h.Active, ", ") + "."
		} else {
			detail += " New writes have recovered; earlier evidence may remain incomplete."
		}
		items = append(items, PostureItem{Kind: "storage_loss", ID: "storage", Severity: 2,
			Title: "Evidence could not be saved", Detail: detail})
	}
	// A monitor that stopped is a blind spot, not a detail.
	for _, c := range st.Collectors {
		if !c.Running || c.Abandoned {
			items = append(items, PostureItem{
				Kind: "collector_down", ID: c.Name,
				Title:    humanCollectorTitle(c.Name, c.Abandoned),
				Severity: 2,
				Detail:   humanCollectorDetail(c.Name, c.LastError),
			})
		}
	}
	// Liveness is not coverage: the worst failure mode a monitor can have is
	// reporting green while blind (both audited live: the eslogger spool
	// untouched for days, zero hook events for 17h, all "healthy").
	if st.ActiveAgents > 0 {
		items = append(items, silentCollectorItems(st)...)
		if st.Coverage != nil {
			items = append(items, harnessUncoveredItems(st.Coverage.Harnesses)...)
		}
		if item := guardHookUnregisteredItem(st); item != nil {
			items = append(items, *item)
		}
	}
	return items
}

// attentionQueue returns the headline items and the grouped queue from one
// pass. Signals without a PID join a live session only when the agent name
// identifies exactly one; ambiguous work stays in an agent-level group.
func (a *API) attentionQueue(st Status, patterns []model.Pattern) ([]PostureItem, []AttentionGroup) {
	var sessions []attentionSession
	if a.resources != nil {
		for _, s := range a.resources().Sessions {
			sess := attentionSession{
				key:          firstNonEmpty([]string{s.Key, fmt.Sprint(s.RootPID)}),
				agent:        s.Name,
				workspace:    s.Workspace,
				label:        firstNonEmpty([]string{cwdBase(s.Workspace), s.Name, "Unknown"}),
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
				label:        firstNonEmpty([]string{cwdBase(t.Root.CWD), t.Root.Name, "Unknown"}),
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
	agentGroup := func(agent string) *AttentionGroup {
		key := "agent:" + firstNonEmpty([]string{agent, "unattributed"})
		if g := groups[key]; g != nil {
			return g
		}
		g := &AttentionGroup{
			Key: key, Label: firstNonEmpty([]string{agent, "Unattributed"}) + " activity",
			Agent: firstNonEmpty([]string{agent, "unknown"}), Items: []AttentionItem{},
		}
		groups[key] = g
		return g
	}
	facts := map[string]*agentGroupFacts{}
	factsFor := func(g *AttentionGroup) *agentGroupFacts {
		if !strings.HasPrefix(g.Key, "agent:") {
			return nil
		}
		if facts[g.Key] == nil {
			facts[g.Key] = newAgentGroupFacts()
		}
		return facts[g.Key]
	}
	items := []PostureItem{}
	add := func(g *AttentionGroup, headline PostureItem, item AttentionItem) {
		items = append(items, headline)
		g.Items = append(g.Items, item)
	}

	// Flags — the security signal. Unacted only: a flag the operator already
	// reviewed/dismissed must not keep demanding attention. Headline severity
	// follows the disposition: an advisor-confirmed benign flag is a queue
	// item, not a "critical — act now". Flags a pattern covers are ONE
	// pattern item (headline and group), in the group of its newest flag.
	patternOf := map[string]int{}
	for i, p := range patterns {
		for _, id := range p.FlagIDs {
			patternOf[id] = i
		}
	}
	patternAdded := map[int]bool{}
	for _, f := range a.attentionFlags() {
		if i, ok := patternOf[f.ID]; ok {
			if !patternAdded[i] {
				patternAdded[i] = true
				p := patterns[i]
				d := p.Disposition
				priority := 1
				if d.State == model.DispositionCritical {
					priority = 2
				}
				g := groupFor(f.Agent, f.PID)
				if gf := factsFor(g); gf != nil {
					gf.addPattern(p)
				}
				add(g, PostureItem{
					Kind: "pattern", ID: p.Key,
					Title:     fmt.Sprintf("%s — %d×", p.Title, p.Count),
					Severity:  dispositionSeverity(d),
					Detail:    p.Summary,
					Timestamp: p.Last.UTC().Format(time.RFC3339),
				}, AttentionItem{
					Kind: "pattern", Priority: priority, ID: p.Key,
					Count: p.Count, Title: p.Title, Detail: p.Summary,
					Disposition: &d, Rule: p.Rule,
				})
			}
			continue
		}
		d := dispositionFor(f)
		detail := f.Rule
		if len(f.Evidence) > 0 {
			detail = f.Rule + " — " + f.Evidence[0].String()
		}
		item := AttentionItem{
			Kind: "flag", Priority: 2, ID: f.ID,
			Title: "Critical finding", Detail: detail, Disposition: &d,
		}
		switch {
		case d.State == model.DispositionBenignLikely:
			item.Priority = 1
			item.Title = "Finding, likely benign"
		case f.Severity < 3:
			item.Priority = 1
			item.Title = humanFlagTitle(f.Rule)
		}
		g := groupFor(f.Agent, f.PID)
		if gf := factsFor(g); gf != nil {
			gf.addFlag(f)
		}
		add(g, PostureItem{
			Kind: "flag", ID: f.ID,
			Title:     humanFlagTitle(f.Rule),
			Severity:  dispositionSeverity(d),
			Detail:    d.Text + " — " + firstEvidence(f.Evidence),
			Timestamp: f.TS.UTC().Format(time.RFC3339),
		}, item)
	}

	// Guard prompts waiting — the operator is actively being asked.
	if a.guardBroker != nil {
		for _, p := range a.guardBroker.Pending() {
			tool := firstNonEmpty([]string{p.Tool, "Tool"})
			path := firstNonEmpty([]string{p.Path, "a protected path"})
			add(groupFor(p.Agent, 0), PostureItem{
				Kind: "guard_pending", ID: p.ID,
				Title:     p.Agent + " wants " + humanPath(p.Path),
				Severity:  1,
				Detail:    "Rule: " + p.RuleID,
				Timestamp: p.TS,
			}, AttentionItem{
				Kind: "guard", Priority: 5, ID: p.ID,
				Title:  "Guard decision",
				Detail: tool + " wants access to " + path,
				Rule:   p.RuleID, Path: p.Path,
				ScopeText: p.ScopeText, Advisor: p.Advisor,
			})
		}
	}

	// A repeated connection is a decision only when the episode is recurring,
	// attributable, and not already covered by an expected-egress rule. One
	// episode may span ended sessions; keep it at agent level rather than
	// assigning it to whichever session happens to be live now.
	for _, e := range a.egressCandidates() {
		action := ""
		scopeText := "Activity scope is incomplete; only this destination can be expected."
		if e.ScopeComplete {
			action = "scope"
			scopeText = fmt.Sprintf("All destinations for %s · %s · %s", e.Scope.ExePath, e.Scope.Harness, e.Scope.Workspace)
		}
		detail := fmt.Sprintf("%d calls to %s:%d (%s) on a recurring schedule.", e.Count, e.Host, e.Port, e.Protocol)
		add(agentGroup(e.Scope.Agent), PostureItem{
			Kind: "recurring_egress", ID: e.ID, Title: "Recurring connection needs review",
			Severity: 1, Detail: detail, Timestamp: e.LastSeen.UTC().Format(time.RFC3339),
		}, AttentionItem{
			Kind: "recurring_egress", Priority: 1, ID: e.ID, Action: action,
			Title: "Recurring connection", Detail: detail, ScopeText: scopeText, Count: e.Count,
		})
	}

	// Incidents not yet resolved: critical ones (severity 3) and high ones
	// (severity 2) keep their risk; any other open more than 72h is a queue
	// item going stale, not a finding.
	for _, inc := range a.store.RecentIncidents(25) {
		wf, _ := a.store.IncidentStatus(inc.ID)
		status := firstNonEmpty([]string{wf.Status, "open"})
		critical := inc.Risk == model.RiskCritical
		high := inc.Risk == model.RiskHigh
		aging := !critical && !high && time.Since(inc.Timestamp) > 72*time.Hour
		if status != "open" || (!critical && !high && !aging) {
			continue
		}
		detail := firstNonEmpty([]string{inc.Summary, inc.Rule, "A security incident needs review."})
		headline := PostureItem{
			Kind: "incident", ID: inc.ID,
			Title:    "Open incident: " + humanFlagTitle(inc.Rule),
			Severity: 2,
			Detail:   detail,
		}
		item := AttentionItem{
			Kind: "incident", Priority: 3, ID: inc.ID,
			Title: "Open incident", Detail: detail, Status: status,
		}
		switch {
		case critical:
			headline.Severity = 3
			item.Title = "Critical incident"
		case aging:
			headline.Title = "Aging incident: " + humanFlagTitle(inc.Rule)
			headline.Severity = 1
			headline.Detail = "open more than 3 days — resolve or acknowledge"
			item.Priority = 1
			item.Title = "Aging incident"
		}
		add(groupFor(inc.Agent, inc.PID), headline, item)
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
		add(groupFor(s.agent, s.rootPID), PostureItem{
			Kind: "resource_pressure", ID: s.control.PendingID,
			Title:    "Resource pressure: " + s.label,
			Severity: 1,
			Detail:   detail,
		}, AttentionItem{
			Kind: "resource", Priority: 4, ID: s.control.PendingID,
			Action: firstNonEmpty([]string{string(s.control.NextAction), "intervention"}),
			Title:  "Resource pressure", Detail: detail,
		})
	}

	live := map[int32]bool{}
	for pid := range byPID {
		live[pid] = true
	}
	for _, t := range st.Trees {
		live[t.Root.PID] = true
		for _, c := range t.Children {
			live[c.PID] = true
		}
	}
	for key, gf := range facts {
		groups[key].Summary = gf.summary(live)
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
	return items, out
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

// familyTitle title-cases a plain harness name ("claude" → "Claude"). Any
// other id, e.g. "untagged:node", is returned unchanged: it names a process,
// not a product.
func familyTitle(name string) string {
	if name == "" {
		return "Unknown"
	}
	if !plainHarnessRE.MatchString(name) {
		return name
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

var plainHarnessRE = regexp.MustCompile(`^[a-z0-9-]+$`)

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
