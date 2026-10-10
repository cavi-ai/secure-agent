package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

// Attention queue: computed once here and served from /posture. A signal is
// queued only when the operator must act: a pending guard prompt, a pending
// resource intervention, an open high or critical incident, or a flag,
// pattern or routine group whose disposition is critical. Each is appended
// once as a headline item (Items) and once as an item in exactly one group,
// so needs_you, the console hero and the menubar count the same set.

// AttentionItem priorities (higher first): guard 5, resource 4, incident 3,
// critical flag, pattern and routine 2.
type AttentionItem struct {
	Kind            string                `json:"kind"` // resource | guard | incident | flag | pattern | routine
	Priority        int                   `json:"priority"`
	ID              string                `json:"id,omitempty"`
	Action          string                `json:"action,omitempty"`
	Title           string                `json:"title"`
	Detail          string                `json:"detail,omitempty"`
	Rule            string                `json:"rule,omitempty"`
	Path            string                `json:"path,omitempty"`
	ScopeText       string                `json:"scopeText,omitempty"`
	AvailableScopes []model.ScopeChoice   `json:"available_scopes,omitempty"`
	ReaderExe       string                `json:"reader_exe,omitempty"`
	Status          string                `json:"status,omitempty"`
	Count           int                   `json:"count,omitempty"`
	Hosts           []string              `json:"hosts,omitempty"`
	Advisor         *model.AdvisorVerdict `json:"advisor,omitempty"`
	// Disposition is set on flag items (the same verdict /flags/{id}/explain
	// serves) and pattern items (the worst open flag's).
	Disposition *model.Disposition       `json:"disposition,omitempty"`
	Assessment  *model.FindingAssessment `json:"assessment,omitempty"`
	Review      *model.ReviewRecord      `json:"review,omitempty"`
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

// machineAttentionItems are the signals no agent owns: dead collectors, and
// while agents are active, silent collectors and missing hooks.
func machineAttentionItems(now time.Time, st Status, hookGap *PostureItem) []PostureItem {
	var items []PostureItem
	if h := st.EgressProjectionHealth; h != nil && (h.QueueDrops > 0 || h.WriteFailures > 0) {
		detail := fmt.Sprintf("%d observations missed the summary queue; %d summary writes failed since daemon start. Recurring egress summaries may be incomplete. Connection evidence has separate storage health.", h.QueueDrops, h.WriteFailures)
		if h.WriteFailing {
			detail += " Summary writes are still failing."
		} else if h.WriteFailures > 0 {
			detail += " New summary writes have recovered."
		}
		items = append(items, PostureItem{Kind: "projection_loss", ID: "egress", Severity: 2, Title: "Recurring egress summary missed activity", Detail: detail})
	}
	if st.OTLPDropped > 0 {
		items = append(items, PostureItem{Kind: "export_loss", ID: "otlp", Severity: 2, Title: "Trace export lost spans", Detail: fmt.Sprintf("%d spans could not be exported since daemon start. Local evidence is retained separately.", st.OTLPDropped)})
	}
	if st.BusDropping {
		items = append(items, PostureItem{Kind: "event_loss", ID: "event-bus", Severity: 2,
			Title:  "Telemetry was dropped",
			Detail: fmt.Sprintf("%d subscriber deliveries dropped since daemon start. Monitoring history may be incomplete.", st.BusDrops)})
	}
	if h := st.StorageHealth; h != nil && len(h.ReadActive) > 0 {
		items = append(items, PostureItem{Kind: "storage_read_failure", ID: "storage-reads", Severity: 2, Title: "Evidence could not be read", Detail: "Last known activity may be stale. Reads failing: " + strings.Join(h.ReadActive, ", ") + "."})
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
		items = append(items, silentCollectorItems(now, st)...)
		if st.Coverage != nil {
			items = append(items, harnessUncoveredItems(st.Coverage.Harnesses)...)
		}
		if hookGap != nil {
			items = append(items, *hookGap)
		}
	}
	return items
}

type attentionQueueResult struct {
	Items  []PostureItem
	Groups []AttentionGroup
}

func deriveAttention(in postureInputs) attentionQueueResult {
	st, patterns, routine := in.Status, in.Patterns, in.Routine
	var sessions []attentionSession
	if len(in.Resources) > 0 {
		for _, s := range in.Resources {
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

	// Flags — the security signal. Unacted only, and only when the
	// disposition is critical: warning and benign-likely flags stay in the
	// findings history. Flags a routine group covers are ONE routine item in
	// the routine group, whichever agents raised them; flags a pattern covers
	// are ONE pattern item (headline and group), in the group of its newest
	// flag.
	routineOf := map[string]int{}
	for i, rg := range routine {
		for _, id := range rg.FlagIDs {
			routineOf[id] = i
		}
	}
	routineAdded := map[int]bool{}
	patternOf := map[string]int{}
	for i, p := range patterns {
		for _, id := range p.FlagIDs {
			patternOf[id] = i
		}
	}
	patternAdded := map[int]bool{}
	coveredReviews := map[string]bool{}
	for _, r := range in.Reviews {
		if !r.EvidenceAvailable || r.Context.Attribution != "stored-session" {
			continue
		}
		coveredReviews[r.ID] = true
		severity := assessmentSeverity(r.Assessment, r.Severity)
		if severity < 3 {
			continue
		}
		key := "session:" + r.Context.SessionID
		g := groups[key]
		if g == nil {
			g = &AttentionGroup{Key: key, Label: firstNonEmpty([]string{cwdBase(r.Context.Workspace), r.Agent, "Session"}), Agent: r.Agent, Workspace: r.Context.Workspace, Summary: "Recorded session " + r.Context.SessionID, Items: []AttentionItem{}}
			groups[key] = g
		}
		add(g, PostureItem{Kind: "review", ID: r.ID, Title: humanFlagTitle(r.Context.Rule), Severity: severity, Detail: r.Assessment.Reason, Timestamp: r.LastSeen.UTC().Format(time.RFC3339)}, AttentionItem{Kind: "review", ID: r.ID, Priority: 1 + severity/3, Title: humanFlagTitle(r.Context.Rule), Detail: r.Assessment.Reason, Count: r.Count, Assessment: &r.Assessment, Review: &r})
	}
	for _, f := range in.Flags {
		if f.Rule == readConnectRule {
			if r, ok := in.FlagReviews[f.ID]; ok && (coveredReviews[r.ID] || r.Context.Attribution == "stored-session" && r.ReviewState != "unreviewed") {
				continue
			}
		}
		if i, ok := routineOf[f.ID]; ok {
			if !routineAdded[i] {
				routineAdded[i] = true
				rg := routine[i]
				d := rg.Disposition
				severity := f.Severity
				if rg.Assessment != nil {
					severity = assessmentSeverity(*rg.Assessment, 0)
				}
				if severity < 3 {
					continue
				}
				g := groups[routineGroupKey]
				if g == nil {
					g = &AttentionGroup{Key: routineGroupKey, Label: "Recurring across agents", Items: []AttentionItem{},
						Summary: "The same process reading the same files under several agents"}
					groups[routineGroupKey] = g
				}
				add(g, PostureItem{
					Kind: "routine", ID: rg.Key,
					Title:     fmt.Sprintf("Recurring read — %d×", rg.Count),
					Severity:  severity,
					Detail:    rg.Summary,
					Timestamp: f.TS.UTC().Format(time.RFC3339),
				}, AttentionItem{
					Kind: "routine", Priority: 2, ID: rg.Key,
					Count: rg.Count, Title: "Recurring read", Detail: rg.Summary,
					Disposition: &d, Assessment: rg.Assessment, Rule: readConnectRule,
				})
			}
			continue
		}
		if i, ok := patternOf[f.ID]; ok {
			if !patternAdded[i] {
				patternAdded[i] = true
				p := patterns[i]
				d := p.Disposition
				severity := f.Severity
				if p.Assessment != nil {
					severity = assessmentSeverity(*p.Assessment, 0)
				}
				if severity < 3 {
					continue
				}
				g := groupFor(f.Agent, f.PID)
				if gf := factsFor(g); gf != nil {
					gf.addPattern(p)
				}
				add(g, PostureItem{
					Kind: "pattern", ID: p.Key,
					Title:     fmt.Sprintf("%s — %d×", p.Title, p.Count),
					Severity:  severity,
					Detail:    p.Summary,
					Timestamp: p.Last.UTC().Format(time.RFC3339),
				}, AttentionItem{
					Kind: "pattern", Priority: 2, ID: p.Key,
					Count: p.Count, Title: p.Title, Detail: p.Summary,
					Disposition: &d, Assessment: p.Assessment, Rule: p.Rule,
				})
			}
			continue
		}
		d := dispositionFor(f)
		assessment := assessmentForFlag(f)
		severity := assessmentSeverity(assessment, f.Severity)
		if severity < 3 {
			continue
		}
		detail := f.Rule
		if len(f.Evidence) > 0 {
			detail = f.Rule + " — " + f.Evidence[0].String()
		}
		item := AttentionItem{
			Kind: "flag", Priority: 2, ID: f.ID,
			Title: "Critical finding", Detail: detail, Disposition: &d, Assessment: &assessment,
		}
		g := groupFor(f.Agent, f.PID)
		if gf := factsFor(g); gf != nil {
			gf.addFlag(f)
		}
		add(g, PostureItem{
			Kind: "flag", ID: f.ID,
			Title:     humanFlagTitle(f.Rule),
			Severity:  severity,
			Detail:    assessment.Reason,
			Timestamp: f.TS.UTC().Format(time.RFC3339),
		}, item)
	}

	// Guard prompts waiting — the operator is actively being asked.
	for _, p := range in.Pending {
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
			AvailableScopes: p.AvailableScopes, ReaderExe: p.ReaderExe,
		})
	}

	// Open incidents of high or critical risk; lower-risk ones stay in the
	// findings history.
	for _, inc := range in.Incidents {
		if r, ok := in.FlagReviews[inc.FlagID]; ok && r.Context.Attribution == "stored-session" {
			continue
		}
		status, found := in.IncidentStates[inc.ID]
		if !found {
			continue
		}
		status = firstNonEmpty([]string{status, "open"})
		critical := inc.Risk == model.RiskCritical
		high := inc.Risk == model.RiskHigh
		if status != "open" || (!critical && !high) {
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
		if critical {
			headline.Severity = 3
			item.Title = "Critical incident"
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
		if ri, rj := out[i].Key == routineGroupKey, out[j].Key == routineGroupKey; ri != rj {
			return ri
		}
		if len(out[i].Items) != len(out[j].Items) {
			return len(out[i].Items) > len(out[j].Items)
		}
		return out[i].Label < out[j].Label
	})
	return attentionQueueResult{Items: items, Groups: out}
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
