package posture

import (
	"cmp"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
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

// Inputs is a snapshot of the facts needed for one derivation. Storage
// and live-service reads happen at the boundary; ranking has no handler access.
type Inputs struct {
	Status              Status
	Generated           time.Time
	Patterns            []model.Pattern
	Routine             []model.RoutineGroup
	Resources           []resource.Session
	HookGap             *PostureItem
	Pending             []guard.Pending
	Flags               []model.Flag
	Reviews             []model.ReviewRecord
	FlagReviews         map[string]model.ReviewRecord
	Incidents           []model.IncidentReport
	IncidentStates      map[string]string
	IncidentAssessments map[string]model.FindingAssessment
	FailedReads         []string
	HookFindings        []store.SessionHookFinding
	HookHealthTruncated bool
}

// ReadConnectRule is the rule id of a sensitive read followed by a connection.
const ReadConnectRule = "sensitive-read-then-connect"

// RoutineGroupKey is the attention group that holds the routine items.
const RoutineGroupKey = "routine"

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

// AttentionQueue is the derived queue: headline items and their groups.
type AttentionQueue struct {
	Items  []PostureItem
	Groups []AttentionGroup
}

// DeriveAttention builds the attention queue from in; disposition supplies
// the verdict of each flag no routine group or pattern covers.
func DeriveAttention(in Inputs, disposition func(model.Flag) model.Disposition) AttentionQueue {
	b := newAttentionBuilder(in, disposition)
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
	in          Inputs
	disposition func(model.Flag) model.Disposition
	sessions    []attentionSession
	byPID       map[int32]*attentionSession
	byAgent     map[string][]*attentionSession
	groups      map[string]*AttentionGroup
	facts       map[string]*agentGroupFacts
	items       []PostureItem
}

func newAttentionBuilder(in Inputs, disposition func(model.Flag) model.Disposition) *attentionBuilder {
	b := &attentionBuilder{
		in:          in,
		disposition: disposition,
		sessions:    attentionSessions(in),
		byPID:       map[int32]*attentionSession{},
		byAgent:     map[string][]*attentionSession{},
		groups:      map[string]*AttentionGroup{},
		facts:       map[string]*agentGroupFacts{},
		items:       []PostureItem{},
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
func attentionSessions(in Inputs) []attentionSession {
	var sessions []attentionSession
	for _, s := range in.Resources {
		sess := attentionSession{
			key:          cmp.Or(s.Key, fmt.Sprint(s.RootPID)),
			agent:        s.Name,
			workspace:    s.Workspace,
			label:        cmp.Or(WorkspaceName(s.Workspace), s.Name, "Unknown"),
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
			label:        cmp.Or(WorkspaceName(t.Root.CWD), t.Root.Name, "Unknown"),
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
		return b.keyed("agent:"+cmp.Or(agent, "unattributed"), AttentionGroup{
			Label: cmp.Or(agent, "Unattributed") + " activity",
			Agent: cmp.Or(agent, "unknown"),
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
		key, label := "hook-host:"+r.ForwarderID, FamilyTitle(r.Harness)+" forwarding host"
		if r.SessionID != "" {
			key, label = "durable-session:"+r.SessionID, "Host-reported session "+r.SessionID
		}
		g := b.keyed(key, AttentionGroup{Label: label, Agent: r.Harness})
		id, title := "hook-delivery:"+r.ForwarderID, FamilyTitle(r.Harness)+" hook delivery needs attention"
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
		g := b.keyed("session:"+r.Context.SessionID, AttentionGroup{Label: cmp.Or(WorkspaceName(r.Context.Workspace), r.Agent, "Session"), Agent: r.Agent, Workspace: r.Context.Workspace, Summary: "Recorded session " + r.Context.SessionID})
		b.add(g, PostureItem{Kind: "review", ID: r.ID, Title: HumanFlagTitle(r.Context.Rule), Severity: severity, Detail: r.Assessment.Reason, Timestamp: r.LastSeen.UTC().Format(time.RFC3339)}, AttentionItem{Kind: "review", ID: r.ID, Priority: 1 + severity/3, Title: HumanFlagTitle(r.Context.Rule), Detail: r.Assessment.Reason, Count: r.Count, Assessment: &r.Assessment, Review: &r})
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
		if f.Rule == ReadConnectRule {
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
	g := b.keyed(RoutineGroupKey, AttentionGroup{Label: "Recurring across agents",
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
		Disposition: &d, Assessment: rg.Assessment, Rule: ReadConnectRule,
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
	d := b.disposition(f)
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
		Title:     HumanFlagTitle(f.Rule),
		Severity:  severity,
		Detail:    assessment.Reason,
		Timestamp: f.TS.UTC().Format(time.RFC3339),
	}, item)
}

// addGuardPending adds the guard prompts waiting on the operator.
func (b *attentionBuilder) addGuardPending() {
	for _, p := range b.in.Pending {
		tool := cmp.Or(p.Tool, "Tool")
		path := cmp.Or(p.Path, "a protected path")
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
		// Older reports promoted routine tool-output/send records to high
		// risk. Additional, missing, credential or injection evidence still pages.
		if inc.Rule == "untrusted-egress" && inc.AggregateCount <= 1 &&
			b.in.IncidentAssessments[inc.FlagID].Risk == "review" && len(inc.RotateList) == 0 {
			continue
		}
		status, found := b.in.IncidentStates[inc.ID]
		if !found {
			continue
		}
		status = cmp.Or(status, "open")
		critical := inc.Risk == model.RiskCritical
		high := inc.Risk == model.RiskHigh
		if status != "open" || (!critical && !high) {
			continue
		}
		detail := cmp.Or(inc.Summary, inc.Rule, "A security incident needs review.")
		headline := PostureItem{
			Kind: "incident", ID: inc.ID,
			Title:    "Open incident: " + HumanFlagTitle(inc.Rule),
			Severity: 2,
			Detail:   detail,
		}
		item := AttentionItem{
			Kind: "incident", Priority: 3, ID: inc.ID,
			Title: "Open incident", Detail: detail, Status: status, Rule: inc.Rule,
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
			Action: cmp.Or(string(s.control.NextAction), "intervention"),
			Title:  "Resource pressure", Detail: detail,
		})
	}
}

// result summarizes agent groups against the live PIDs and orders the
// non-empty groups: highest item priority, then the routine group, then more
// items, then label.
func (b *attentionBuilder) result() AttentionQueue {
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
		if ri, rj := out[i].Key == RoutineGroupKey, out[j].Key == RoutineGroupKey; ri != rj {
			return ri
		}
		if len(out[i].Items) != len(out[j].Items) {
			return len(out[i].Items) > len(out[j].Items)
		}
		return out[i].Label < out[j].Label
	})
	return AttentionQueue{Items: b.items, Groups: out}
}

// WorkspaceName is the last element of a workspace path; "" for an empty path.
func WorkspaceName(cwd string) string {
	s := strings.TrimRight(cwd, "/")
	if s == "" {
		return ""
	}
	if i := strings.LastIndexAny(s, "/\\"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// FamilyTitle title-cases a plain harness name ("claude" → "Claude"). Any
// other id, e.g. "untagged:node", is returned unchanged: it names a process,
// not a product.
func FamilyTitle(name string) string {
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

// humanPath shortens an absolute path to its tail for a headline.
func humanPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}

// HumanFlagTitle maps rule ids to operator language (mirrors the menubar's
// NotificationManager titles; kept in sync manually until a shared table).
func HumanFlagTitle(rule string) string {
	switch rule {
	case "proxy-secret-leak":
		return "Secret leaving in agent traffic"
	case "sensitive-read-then-connect":
		return "Sensitive file read near an outside connection"
	case "keychain-access":
		return "Agent touched the keychain"
	case "keychain-security-cli":
		return "Agent ran the macOS keychain tool"
	case "tcc-tamper":
		return "Agent modified macOS privacy permissions (TCC)"
	case "launch-item-change":
		return "Agent changed a background item"
	case "trust-change":
		return "Agent changed what macOS trusts"
	case "xprotect-detection":
		return "XProtect detected malware"
	case "proxy-prompt-injection":
		return "Prompt injection in a response"
	case "proxy-inspection-incomplete":
		return "Proxy request inspection was incomplete"
	case "secret-in-transcript":
		return "Secret appeared in an agent transcript"
	case "untrusted-egress":
		return "Data sent after reading untrusted content"
	case "proxy-untrusted-egress":
		return "Connection refused after reading untrusted content"
	case "proxy-untrusted-egress-monitored":
		return "Connection after reading untrusted content"
	default:
		return rule
	}
}
