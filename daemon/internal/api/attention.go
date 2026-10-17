package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/hookhealth"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
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
	Tool            string                `json:"tool,omitempty"`
	Workspace       string                `json:"workspace,omitempty"`
	ScopeText       string                `json:"scopeText,omitempty"`
	AvailableScopes []model.ScopeChoice   `json:"available_scopes,omitempty"`
	ReaderExe       string                `json:"reader_exe,omitempty"`
	Status          string                `json:"status,omitempty"`
	Count           int                   `json:"count,omitempty"`
	Hosts           []string              `json:"hosts,omitempty"`
	Advisor         *model.AdvisorVerdict `json:"advisor,omitempty"`
	// Disposition is set on flag items (the same verdict /flags/{id}/explain
	// serves) and pattern items (the worst open flag's).
	Disposition  *model.Disposition           `json:"disposition,omitempty"`
	Assessment   *model.FindingAssessment     `json:"assessment,omitempty"`
	Review       *model.ReviewRecord          `json:"review,omitempty"`
	SessionID    string                       `json:"session_id,omitempty"`
	HookFinding  *hookhealth.Finding          `json:"hook_finding,omitempty"`
	HookDelivery *store.HookForwarderSnapshot `json:"hook_delivery,omitempty"`
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
	b := newAttentionBuilder(in)
	b.addHookFindings()
	b.addHookDeliveries()
	b.addFlags(b.addReviews())
	b.addGuardPending()
	b.addIncidents()
	b.addResourcePressure()
	return b.result()
}

// attentionBuilder holds one derivation's sessions and groups; each add step
// appends one source's items, in queue order.
type attentionBuilder struct {
	in       postureInputs
	sessions []attentionSession
	byPID    map[int32]*attentionSession
	byAgent  map[string][]*attentionSession
	groups   map[string]*AttentionGroup
	facts    map[string]*agentGroupFacts
	items    []PostureItem
}

func newAttentionBuilder(in postureInputs) *attentionBuilder {
	b := &attentionBuilder{
		in:       in,
		sessions: attentionSessions(in),
		byPID:    map[int32]*attentionSession{},
		byAgent:  map[string][]*attentionSession{},
		groups:   map[string]*AttentionGroup{},
		facts:    map[string]*agentGroupFacts{},
		items:    []PostureItem{},
	}
	for i := range b.sessions {
		s := &b.sessions[i]
		for _, pid := range s.pids {
			b.byPID[pid] = s
		}
		if s.rootPID != 0 {
			b.byPID[s.rootPID] = s
		}
		if k := strings.ToLower(s.agent); k != "" {
			b.byAgent[k] = append(b.byAgent[k], s)
		}
	}
	return b
}

// attentionSessions lists the resource tracker's sessions, or one session
// per process tree when it has none.
func attentionSessions(in postureInputs) []attentionSession {
	var sessions []attentionSession
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
	if len(sessions) > 0 {
		return sessions
	}
	for _, t := range in.Status.Trees {
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
	return sessions
}

// keyed returns the group stored under key, creating it from init.
func (b *attentionBuilder) keyed(key string, init AttentionGroup) *AttentionGroup {
	if g := b.groups[key]; g != nil {
		return g
	}
	init.Key, init.Items = key, []AttentionItem{}
	b.groups[key] = &init
	return &init
}

// groupFor is the group of the session that owns pid, else of the agent's
// only session, else of the agent itself.
func (b *attentionBuilder) groupFor(agent string, pid int32) *AttentionGroup {
	sess := b.byPID[pid]
	if sess == nil {
		if matches := b.byAgent[strings.ToLower(agent)]; len(matches) == 1 {
			sess = matches[0]
		}
	}
	if sess == nil {
		return b.keyed("agent:"+firstNonEmpty([]string{agent, "unattributed"}), AttentionGroup{
			Label: firstNonEmpty([]string{agent, "Unattributed"}) + " activity",
			Agent: firstNonEmpty([]string{agent, "unknown"}),
		})
	}
	return b.keyed("session:"+sess.key, AttentionGroup{
		Label:        sess.label,
		Agent:        sess.agent,
		Workspace:    sess.workspace,
		RootPID:      sess.rootPID,
		PIDs:         sess.pids,
		RSSBytes:     sess.rssBytes,
		CPUPercent:   sess.cpuPercent,
		ProcessCount: sess.processCount,
	})
}

// factsFor is the fact sheet of an agent group; session groups have none.
func (b *attentionBuilder) factsFor(g *AttentionGroup) *agentGroupFacts {
	if !strings.HasPrefix(g.Key, "agent:") {
		return nil
	}
	if b.facts[g.Key] == nil {
		b.facts[g.Key] = newAgentGroupFacts()
	}
	return b.facts[g.Key]
}

// add appends item to g and its headline to the queue.
func (b *attentionBuilder) add(g *AttentionGroup, headline PostureItem, item AttentionItem) {
	headline.Assessment = item.Assessment
	if item.Assessment != nil && item.Assessment.Risk == "unknown" {
		headline.Title = "Finding needs evidence review"
	}
	b.items = append(b.items, headline)
	g.Items = append(g.Items, item)
}

// addHookFindings adds hook repair findings. They keep their durable session
// identity rather than borrow a PID or another session merely because its
// harness or workspace matches.
func (b *attentionBuilder) addHookFindings() {
	for _, hf := range b.in.HookFindings {
		f := hf.Finding
		g := b.keyed("durable-session:"+hf.SessionID, AttentionGroup{Label: "Session " + hf.SessionID, Agent: f.Harness})
		b.add(g, PostureItem{Kind: "hook", ID: f.ID, Title: f.Title, Severity: 1, Detail: f.Detail, Timestamp: f.LastAt.UTC().Format(time.RFC3339Nano)}, AttentionItem{Kind: "hook", Priority: 1, ID: f.ID, SessionID: hf.SessionID, Title: f.Title, Detail: f.Detail, HookFinding: &f})
	}
}

// addHookDeliveries adds the forwarding hosts whose delivery needs action.
func (b *attentionBuilder) addHookDeliveries() {
	h := b.in.Status.HookIngestion
	if h == nil {
		return
	}
	for _, row := range h.Forwarders {
		if row.Assessment.State != "needs-action" {
			continue
		}
		r := row.Report
		key, label := "hook-host:"+r.ForwarderID, familyTitle(r.Harness)+" forwarding host"
		if r.SessionID != "" {
			key, label = "durable-session:"+r.SessionID, "Host-reported session "+r.SessionID
		}
		g := b.keyed(key, AttentionGroup{Label: label, Agent: r.Harness})
		id, title := "hook-delivery:"+r.ForwarderID, familyTitle(r.Harness)+" hook delivery needs attention"
		detail := fmt.Sprintf("%d queued completions; inspect the host's current delivery diagnostics.", r.Pending)
		b.add(g, PostureItem{Kind: "hook_delivery", ID: id, Title: title, Detail: detail, Severity: 1, Timestamp: row.ReceivedAt.UTC().Format(time.RFC3339Nano)}, AttentionItem{Kind: "hook_delivery", Priority: 1, ID: id, Title: title, Detail: detail, SessionID: r.SessionID, HookDelivery: &row})
	}
}

// addReviews adds stored-session reviews of severity 3 or more. It returns
// the ID of every stored-session review with evidence; addFlags skips the
// read-connect flags those reviews cover.
func (b *attentionBuilder) addReviews() map[string]bool {
	covered := map[string]bool{}
	for _, r := range b.in.Reviews {
		if !r.EvidenceAvailable || r.Context.Attribution != "stored-session" {
			continue
		}
		covered[r.ID] = true
		severity := model.GroupFindingSeverity(r.Assessment, r.Severity)
		if severity < 3 {
			continue
		}
		g := b.keyed("session:"+r.Context.SessionID, AttentionGroup{Label: firstNonEmpty([]string{cwdBase(r.Context.Workspace), r.Agent, "Session"}), Agent: r.Agent, Workspace: r.Context.Workspace, Summary: "Recorded session " + r.Context.SessionID})
		b.add(g, PostureItem{Kind: "review", ID: r.ID, Title: humanFlagTitle(r.Context.Rule), Severity: severity, Detail: r.Assessment.Reason, Timestamp: r.LastSeen.UTC().Format(time.RFC3339)}, AttentionItem{Kind: "review", ID: r.ID, Priority: 1 + severity/3, Title: humanFlagTitle(r.Context.Rule), Detail: r.Assessment.Reason, Count: r.Count, Assessment: &r.Assessment, Review: &r})
	}
	return covered
}

// addFlags adds the security signal: unacted flags whose disposition is
// critical; warning and benign-likely flags stay in the findings history.
// Flags a routine group covers are ONE routine item in the routine group,
// whichever agents raised them; flags a pattern covers are ONE pattern item
// (headline and group), in the group of its newest flag.
func (b *attentionBuilder) addFlags(coveredReviews map[string]bool) {
	routineOf := map[string]int{}
	for i, rg := range b.in.Routine {
		for _, id := range rg.FlagIDs {
			routineOf[id] = i
		}
	}
	patternOf := map[string]int{}
	for i, p := range b.in.Patterns {
		for _, id := range p.FlagIDs {
			patternOf[id] = i
		}
	}
	routineAdded, patternAdded := map[int]bool{}, map[int]bool{}
	for _, f := range b.in.Flags {
		if f.Rule == readConnectRule {
			if r, ok := b.in.FlagReviews[f.ID]; ok && (coveredReviews[r.ID] || r.Context.Attribution == "stored-session" && r.ReviewState != "unreviewed") {
				continue
			}
		}
		if i, ok := routineOf[f.ID]; ok {
			if !routineAdded[i] {
				routineAdded[i] = true
				b.addRoutine(b.in.Routine[i], f)
			}
			continue
		}
		if i, ok := patternOf[f.ID]; ok {
			if !patternAdded[i] {
				patternAdded[i] = true
				b.addPattern(b.in.Patterns[i], f)
			}
			continue
		}
		b.addFlag(f)
	}
}

// addRoutine adds routine group rg, reached through its flag f.
func (b *attentionBuilder) addRoutine(rg model.RoutineGroup, f model.Flag) {
	d := rg.Disposition
	severity := f.Severity
	if rg.Assessment != nil {
		severity = model.GroupFindingSeverity(*rg.Assessment, 0)
	}
	if severity < 3 {
		return
	}
	g := b.keyed(routineGroupKey, AttentionGroup{Label: "Recurring across agents",
		Summary: "The same process reading the same files under several agents"})
	b.add(g, PostureItem{
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

// addPattern adds pattern p to the group of its flag f.
func (b *attentionBuilder) addPattern(p model.Pattern, f model.Flag) {
	d := p.Disposition
	severity := f.Severity
	if p.Assessment != nil {
		severity = model.GroupFindingSeverity(*p.Assessment, 0)
	}
	if severity < 3 {
		return
	}
	g := b.groupFor(f.Agent, f.PID)
	if gf := b.factsFor(g); gf != nil {
		gf.addPattern(p)
	}
	b.add(g, PostureItem{
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

// addFlag adds a flag no routine group or pattern covers.
func (b *attentionBuilder) addFlag(f model.Flag) {
	d := dispositionFor(f)
	assessment := model.AssessFinding(f)
	severity := model.GroupFindingSeverity(assessment, f.Severity)
	if severity < 3 {
		return
	}
	detail := f.Rule
	if len(f.Evidence) > 0 {
		detail = f.Rule + " — " + f.Evidence[0].String()
	}
	item := AttentionItem{
		Kind: "flag", Priority: 2, ID: f.ID,
		Title: "Critical finding", Detail: detail, Disposition: &d, Assessment: &assessment,
	}
	g := b.groupFor(f.Agent, f.PID)
	if gf := b.factsFor(g); gf != nil {
		gf.addFlag(f)
	}
	b.add(g, PostureItem{
		Kind: "flag", ID: f.ID,
		Title:     humanFlagTitle(f.Rule),
		Severity:  severity,
		Detail:    assessment.Reason,
		Timestamp: f.TS.UTC().Format(time.RFC3339),
	}, item)
}

// addGuardPending adds the guard prompts waiting on the operator.
func (b *attentionBuilder) addGuardPending() {
	for _, p := range b.in.Pending {
		tool := firstNonEmpty([]string{p.Tool, "Tool"})
		path := firstNonEmpty([]string{p.Path, "a protected path"})
		b.add(b.groupFor(p.Agent, 0), PostureItem{
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
			Tool: p.Tool, Workspace: p.Workspace, SessionID: p.SessionID,
			ScopeText: p.ScopeText, Advisor: p.Advisor,
			AvailableScopes: p.AvailableScopes, ReaderExe: p.ReaderExe,
		})
	}
}

// addIncidents adds open incidents of high or critical risk; lower-risk ones
// stay in the findings history.
func (b *attentionBuilder) addIncidents() {
	for _, inc := range b.in.Incidents {
		if r, ok := b.in.FlagReviews[inc.FlagID]; ok && r.Context.Attribution == "stored-session" {
			continue
		}
		status, found := b.in.IncidentStates[inc.ID]
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
		b.add(b.groupFor(inc.Agent, inc.PID), headline, item)
	}
}

// addResourcePressure adds the sessions with a pending intervention decision.
func (b *attentionBuilder) addResourcePressure() {
	for i := range b.sessions {
		s := &b.sessions[i]
		if s.control == nil || s.control.PendingID == "" {
			continue
		}
		detail := "This session exceeded its configured resource budget."
		if len(s.diagnoses) > 0 && s.diagnoses[0].Summary != "" {
			detail = s.diagnoses[0].Summary
		}
		b.add(b.groupFor(s.agent, s.rootPID), PostureItem{
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
}

// result summarizes agent groups against the live PIDs and orders the
// non-empty groups: highest item priority, then the routine group, then more
// items, then label.
func (b *attentionBuilder) result() attentionQueueResult {
	live := map[int32]bool{}
	for pid := range b.byPID {
		live[pid] = true
	}
	for _, t := range b.in.Status.Trees {
		live[t.Root.PID] = true
		for _, c := range t.Children {
			live[c.PID] = true
		}
	}
	for key, gf := range b.facts {
		b.groups[key].Summary = gf.summary(live)
	}

	out := make([]AttentionGroup, 0, len(b.groups))
	for _, g := range b.groups {
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
	return attentionQueueResult{Items: b.items, Groups: out}
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
