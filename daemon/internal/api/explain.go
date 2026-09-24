package api

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// explainListCap: /flags and /snapshot stamp the explanation on this many
// unacknowledged flags (the rows the console renders); the rest stay raw.
const explainListCap = 25

// explainContextWindow bounds the tool-call and model lookup around the
// flagged moment.
const explainContextWindow = 60 * time.Second

// explainHome is the home directory owner labels resolve against (a var so
// tests pin it).
var explainHome = func() string {
	h, _ := os.UserHomeDir()
	return h
}

// categoryLabels: subject category → display label and its article.
var categoryLabels = map[string]struct{ label, article string }{
	sensitive.CatEnvFile.String():        {"environment file", "an"},
	sensitive.CatSSHKey.String():         {"SSH private key", "an"},
	sensitive.CatAWS.String():            {"AWS credentials", ""},
	sensitive.CatKeychain.String():       {"keychain", "a"},
	sensitive.CatKeychainSystem.String(): {"system trust store", "a"},
	sensitive.CatOther.String():          {"sensitive file", "a"},
	transcriptCategory:                   {"agent transcript", "an"},
}

const transcriptCategory = "transcript"

// guardRuleForCategory: subject category → the guard rule a per-path allow
// is recorded under.
var guardRuleForCategory = map[string]string{
	sensitive.CatEnvFile.String():  "env-files",
	sensitive.CatSSHKey.String():   "ssh-keys",
	sensitive.CatAWS.String():      "cloud-creds",
	sensitive.CatKeychain.String(): "keychain",
}

// explainEnv is what an explanation reads besides the flag, resolved once
// per request so a list costs one status probe and one session read per
// session, not one per flag.
type explainEnv struct {
	home     string
	live     map[int32]AgentSummary
	sessions map[string]*model.Session
}

func (a *API) newExplainEnv() *explainEnv {
	env := &explainEnv{home: strings.TrimRight(explainHome(), "/"), live: map[int32]AgentSummary{}, sessions: map[string]*model.Session{}}
	if a.statusFn != nil {
		for _, ag := range a.statusFn().Agents {
			env.live[ag.PID] = ag
		}
	}
	return env
}

func (a *API) session(env *explainEnv, id string) *model.Session {
	if id == "" {
		return nil
	}
	if s, ok := env.sessions[id]; ok {
		return s
	}
	var out *model.Session
	if s, ok := a.store.GetSession(id); ok {
		out = &s
	}
	env.sessions[id] = out
	return out
}

// lookupFlag reads one stored flag with its advisor verdict attached.
func (a *API) lookupFlag(id string) (model.Flag, bool) {
	f, ok := a.store.GetFlag(id)
	if !ok {
		return f, false
	}
	if v, ok := a.store.AdvisorVerdictFor(f.ID, "flag"); ok {
		f.Advisor = &v
	}
	return f, true
}

// handleFlagExplain serves GET /flags/{id}/explain: the full flag with its
// title and explanation. It owns the /flags/ subtree; the exact
// /flags/acknowledge pattern is more specific and keeps its own handler.
func (a *API) handleFlagExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/flags/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[1] != "explain" || !guardTokenRE.MatchString(parts[0]) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f, ok := a.lookupFlag(parts[0])
	if !ok {
		http.Error(w, "flag not found", http.StatusNotFound)
		return
	}
	f.Title = humanFlagTitle(f.Rule)
	f.Explain = a.explainFlag(f, true)
	writeJSON(w, f)
}

// stampExplains sets Explain on the first explainListCap unacknowledged
// flags, without network lookups.
func (a *API) stampExplains(flags []model.Flag) {
	var env *explainEnv
	n := 0
	for i := range flags {
		if flags[i].Acknowledged || n >= explainListCap {
			continue
		}
		if env == nil {
			env = a.newExplainEnv()
		}
		flags[i].Explain = a.explainFlagIn(flags[i], false, env)
		n++
	}
}

// explainFlag builds the plain-language reading of f. full permits one
// bounded reverse-DNS lookup per bare-IP destination; list stamping passes
// false and reads the identity tables and PTR cache only.
func (a *API) explainFlag(f model.Flag, full bool) *model.FlagExplain {
	return a.explainFlagIn(f, full, a.newExplainEnv())
}

func (a *API) explainFlagIn(f model.Flag, full bool, env *explainEnv) *model.FlagExplain {
	ex := &model.FlagExplain{Disposition: dispositionFor(f)}
	sess := a.session(env, f.SessionID)
	workspace := f.Workspace
	if sess != nil && sess.Workspace != "" {
		workspace = sess.Workspace
	}
	subject := subjectEvidence(f.Evidence)
	var readTS time.Time
	if subject != nil {
		ex.Subject = explainSubject(*subject, workspace, repoName(sess, workspace), env.home)
		if subject.Kind == "read" {
			readTS, _ = time.Parse(time.RFC3339, subject.TS)
		}
	}
	ex.Egress = a.explainEgress(f, readTS, full)
	anchor := readTS
	if anchor.IsZero() {
		anchor = f.TS
	}
	ex.Context = a.explainContext(f, sess, workspace, anchor)
	ex.What = explainWhat(f, ex, sess)
	ex.Actions = a.explainActions(f, ex, env)
	pattern := flagEvidencePath(f)
	if pattern == "" {
		pattern = flagEvidenceHost(f)
	}
	if sum := a.store.LabelSummary(f.Agent, pattern, f.Rule); sum.OK+sum.NotOK > 0 {
		ex.Labels = &sum
	}
	return ex
}

// subjectEvidence is the first evidence item naming a file: a read, a
// keychain access, a transcript, or a violation that carries a path.
func subjectEvidence(evidence []model.EvidenceItem) *model.EvidenceItem {
	for i := range evidence {
		ev := &evidence[i]
		switch {
		case ev.Kind == "read" || ev.Kind == "keychain" || ev.Kind == "transcript":
			return ev
		case ev.Kind == "violation" && strings.HasPrefix(ev.Label, "/"):
			return ev
		}
	}
	return nil
}

func explainSubject(ev model.EvidenceItem, workspace, repo, home string) *model.ExplainSubject {
	var category string
	switch ev.Kind {
	case "transcript":
		category = transcriptCategory
	case "keychain":
		category = sensitive.CatKeychain.String()
	default:
		category = sensitive.CategoryForRule(ev.Rule).String()
	}
	return &model.ExplainSubject{
		Path:          ev.Label,
		Display:       displayPath(ev.Label, home),
		Basename:      filepath.Base(ev.Label),
		Category:      category,
		CategoryLabel: categoryLabels[category].label,
		Rule:          ev.Rule,
		OwnerLabel:    ownerLabel(ev.Label, workspace, repo, home),
	}
}

// displayPath abbreviates the home directory to ~ and middle-truncates to 64
// runes.
func displayPath(path, home string) string {
	d := path
	if home != "" && (path == home || strings.HasPrefix(path, home+"/")) {
		d = "~" + path[len(home):]
	}
	return middleTruncate(d, 64)
}

func middleTruncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	head := (max - 1) / 2
	tail := max - 1 - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
}

// ownerLabel names who a path belongs to: a harness's own config, the
// session's repo, a temp directory, the home directory, or the system.
func ownerLabel(path, workspace, repo, home string) string {
	under := func(dir string) bool {
		dir = strings.TrimRight(dir, "/")
		return dir != "" && (path == dir || strings.HasPrefix(path, dir+"/"))
	}
	switch {
	case home != "" && under(home+"/.claude/skills"):
		return "Claude skills (~/.claude/skills)"
	case home != "" && under(home+"/.claude"):
		return "Claude Code config (~/.claude)"
	case home != "" && under(home+"/.cursor"):
		return "Cursor config"
	case home != "" && under(home+"/.config/opencode"):
		return "opencode config"
	case repo != "" && under(workspace):
		return "repo " + repo
	case under(os.Getenv("TMPDIR")) || under("/var/folders") || under("/private/var/folders") || under("/tmp") || under("/private/tmp"):
		return "temp directory"
	case home != "" && under(home):
		return "home directory"
	default:
		return "system"
	}
}

func repoName(sess *model.Session, workspace string) string {
	if sess != nil && sess.Repo != "" {
		return sess.Repo
	}
	return cwdBase(workspace)
}

// splitHostPort splits a "host:port" evidence label (IPv6 hosts arrive
// unbracketed, so the port is after the last colon).
func splitHostPort(label string) (string, int) {
	i := strings.LastIndex(label, ":")
	if i <= 0 {
		return label, 0
	}
	port, err := strconv.Atoi(label[i+1:])
	if err != nil {
		return label, 0
	}
	return strings.Trim(label[:i], "[]"), port
}

func (a *API) explainEgress(f model.Flag, readTS time.Time, full bool) []model.ExplainEgress {
	var out []model.ExplainEgress
	seen := map[string]bool{}
	for _, ev := range f.Evidence {
		if ev.Kind != "connect" || ev.Label == "" {
			continue
		}
		host, port := splitHostPort(ev.Label)
		key := net.JoinHostPort(host, strconv.Itoa(port))
		if host == "" || seen[key] {
			continue
		}
		seen[key] = true
		id := correlate.IdentifyCached(host)
		if full {
			id = correlate.Identify(host)
		}
		eg := model.ExplainEgress{Host: host, Port: port, Org: id.Org, Name: id.Name, Kind: id.Kind}
		if a.allowlist != nil && f.Agent != "" {
			eg.Allowlisted = a.allowlist.Allows(f.Agent, host)
		}
		if ts, err := time.Parse(time.RFC3339, ev.TS); err == nil && !readTS.IsZero() {
			eg.GapSeconds = ts.Sub(readTS).Seconds()
		}
		out = append(out, eg)
	}
	return out
}

func (a *API) explainContext(f model.Flag, sess *model.Session, workspace string, anchor time.Time) *model.ExplainContext {
	if f.SessionID == "" {
		return nil
	}
	c := &model.ExplainContext{SessionID: f.SessionID, Workspace: workspace}
	if sess != nil {
		c.Harness, c.Repo, c.Branch = sess.Harness, sess.Repo, sess.Branch
	}
	if anchor.IsZero() {
		return c
	}
	if ev, ok := a.nearestEvent(f.SessionID, event.KindToolCall, anchor); ok {
		c.Tool, c.ToolStatus = ev.ToolName, ev.ToolStatus
		at := ev.TS
		c.ToolAt = &at
	}
	if ev, ok := a.nearestEvent(f.SessionID, event.KindModelCall, anchor); ok {
		c.Model = ev.Model
	}
	return c
}

// nearestEvent is the session's event of kind closest in time to anchor,
// within explainContextWindow either side.
func (a *API) nearestEvent(sessionID string, kind event.Kind, anchor time.Time) (event.Event, bool) {
	k := int(kind)
	evs := a.store.QueryEvents(store.EventFilter{
		Kind:      &k,
		SessionID: sessionID,
		Since:     anchor.Add(-explainContextWindow).UTC().Format(time.RFC3339),
		Until:     anchor.Add(explainContextWindow).UTC().Format(time.RFC3339),
		Limit:     200,
	})
	var best event.Event
	bestGap := explainContextWindow + 1
	for _, e := range evs {
		if kind == event.KindModelCall && e.Model == "" {
			continue
		}
		gap := e.TS.Sub(anchor)
		if gap < 0 {
			gap = -gap
		}
		if gap < bestGap {
			best, bestGap = e, gap
		}
	}
	return best, bestGap <= explainContextWindow
}

// explainWhat is the one-sentence account of the flag, from the rule's
// template. No pids; the destination's org over its address.
func explainWhat(f model.Flag, ex *model.FlagExplain, sess *model.Session) string {
	agent := "An agent"
	if f.Agent != "" {
		agent = familyTitle(f.Agent)
	}
	dest := "an outside host"
	if len(ex.Egress) > 0 {
		dest = firstNonEmpty([]string{ex.Egress[0].Org, ex.Egress[0].Host})
	}
	switch f.Rule {
	case "sensitive-read-then-connect":
		what := agent + " read " + subjectPhrase(ex.Subject)
		if len(ex.Egress) == 0 {
			return what + ", then connected out."
		}
		gap := ex.Egress[0].GapSeconds
		if gap < 0 {
			return what + ", " + gapPhrase(gap) + " after reaching " + dest + "."
		}
		return what + ", then reached " + dest + " " + gapPhrase(gap) + " later."
	case "keychain-access":
		if ex.Subject == nil {
			return agent + " opened a keychain file."
		}
		return agent + " opened " + ex.Subject.Basename + " in the keychain."
	case "keychain-security-cli":
		return agent + " ran the keychain tool."
	case "tcc-tamper":
		if label := evidenceLabel(f.Evidence, "tcc"); label != "" {
			return agent + " changed macOS privacy permissions (" + label + ")."
		}
		return agent + " changed macOS privacy permissions."
	case "proxy-secret-leak":
		return agent + " sent " + secretPhrase(violationType(f.Evidence, "proxy-secret-leak")) + " to " + dest + "."
	case "proxy-prompt-injection":
		return "A response to " + agent + " from " + dest + " contained a prompt injection."
	case "secret-in-transcript":
		harness := f.Agent
		if sess != nil && sess.Harness != "" {
			harness = sess.Harness
		}
		what := capitalize(secretPhrase(evidenceRule(f.Evidence, "transcript"))) + " appeared in " + article(familyTitle(harness)) + " transcript"
		if ex.Subject != nil {
			what += " (" + ex.Subject.Basename + ")"
		}
		return what + "."
	default:
		return humanFlagTitle(f.Rule)
	}
}

func subjectPhrase(s *model.ExplainSubject) string {
	if s == nil {
		return "a sensitive file"
	}
	cl := categoryLabels[s.Category]
	label := s.CategoryLabel
	if cl.article != "" {
		label = cl.article + " " + label
	}
	return label + " in " + ownerPhrase(s.OwnerLabel)
}

// ownerPhrase fits a generic owner label into a sentence.
func ownerPhrase(owner string) string {
	switch owner {
	case "home directory":
		return "your home directory"
	case "temp directory":
		return "a temp directory"
	case "system":
		return "a system location"
	default:
		return owner
	}
}

// gapPhrase renders a read→connect gap: "3 s", "2 min", "1 h".
func gapPhrase(seconds float64) string {
	s := int(math.Round(math.Abs(seconds)))
	switch {
	case s < 1:
		return "moments"
	case s < 60:
		return fmt.Sprintf("%d s", s)
	case s < 3600:
		return fmt.Sprintf("%d min", int(math.Round(float64(s)/60)))
	default:
		return fmt.Sprintf("%d h", int(math.Round(float64(s)/3600)))
	}
}

func secretPhrase(kind string) string {
	if kind == "" {
		return "a secret"
	}
	return "a secret (" + kind + ")"
}

// violationType is the detail after "<rule>:" on the first violation item.
func violationType(evidence []model.EvidenceItem, rule string) string {
	label := evidenceLabel(evidence, "violation")
	if rest, ok := strings.CutPrefix(label, rule); ok {
		return strings.TrimPrefix(rest, ":")
	}
	return label
}

func evidenceLabel(evidence []model.EvidenceItem, kind string) string {
	for _, ev := range evidence {
		if ev.Kind == kind {
			return ev.Label
		}
	}
	return ""
}

func evidenceRule(evidence []model.EvidenceItem, kind string) string {
	for _, ev := range evidence {
		if ev.Kind == kind {
			return ev.Rule
		}
	}
	return ""
}

func article(word string) string {
	if word != "" && strings.ContainsRune("AEIOUaeiou", rune(word[0])) {
		return "an " + word
	}
	return "a " + word
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// validMuteHost is the host shape POST /mute accepts: a bare hostname (no
// port, path, userinfo — so no IPv6 literal either).
func validMuteHost(host string) bool {
	return host != "" && !strings.ContainsAny(host, "/:@") && len(host) <= 253
}

// muteAgentRE bounds a mute's agent: a configured agent name or an
// "untagged:<exe>" label ("untagged:claude 2.1.280").
var muteAgentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_. :-]{0,127}$`)

// validMuteAgent accepts empty (every agent) or a bounded agent label.
func validMuteAgent(agent string) bool {
	return agent == "" || muteAgentRE.MatchString(agent)
}

// muteClassNoun names a rule class in a mute label ("Mute keychain access
// for codex").
var muteClassNoun = map[string]string{
	"keychain-access":       "keychain access",
	"keychain-security-cli": "keychain tool runs",
}

// muteRuleHostAction is the served mute-rule-host request for rule at host.
// An agent scopes the mute to that agent and the label names it; no agent
// mutes every agent. False for an agent POST /mute cannot scope to, so the
// served mute never widens to every agent.
func muteRuleHostAction(rule, title, host, agent string) (model.ExplainAction, bool) {
	if !validMuteAgent(agent) {
		return model.ExplainAction{}, false
	}
	label, who := "Stop flagging this for "+host, ""
	body := map[string]any{"rule": rule, "host": host}
	if agent != "" {
		label, who = "Stop flagging this for "+host+" from "+agent, " from "+agent
		body["agent"] = agent
	}
	return model.ExplainAction{
		ID: "mute-rule-host", Label: label,
		Consequence: "\"" + title + "\" stops being flagged for " + host + who + "; the host stays monitored and its open flags of this rule are marked reviewed.",
		Method:      http.MethodPost, Path: "/mute",
		Body: body,
	}, true
}

// muteClassAction is the served mute-class request for a keychain rule;
// false for any other rule. Agent scoping as muteRuleHostAction.
func muteClassAction(rule, title, agent string) (model.ExplainAction, bool) {
	noun := muteClassNoun[rule]
	if noun == "" || !validMuteAgent(agent) {
		return model.ExplainAction{}, false
	}
	label, scope := "Dismiss this flag class", "for every agent"
	body := map[string]any{"rule": rule, "host": "*"}
	if agent != "" {
		label, scope = "Mute "+noun+" for "+agent, "for "+agent+"; other agents still flag"
		body["agent"] = agent
	}
	return model.ExplainAction{
		ID: "mute-class", Label: label,
		Consequence: "\"" + title + "\" stops raising flags " + scope + "; monitoring continues and suppressed hits are counted.",
		Method:      http.MethodPost, Path: "/mute",
		Body: body,
	}, true
}

// muteAgentSuffix is " (agent X)" for an agent-scoped mute, "" otherwise.
func muteAgentSuffix(agent string) string {
	if agent == "" {
		return ""
	}
	return " (agent " + agent + ")"
}

// allowHostLabel is the served allow-host button text. An IPv6 literal never
// appears in it — the popover and web console (web_dist/lib.js
// explainActionLabel) both drop it in favor of "this <Org> address" — while
// a hostname or IPv4 host keeps the readable "Allow <name> for <agent>" form.
func allowHostLabel(name, host, org, agent string) string {
	if strings.Contains(host, ":") {
		if org != "" {
			return "Allow this " + org + " address for " + agent
		}
		return "Allow this address for " + agent
	}
	return "Allow " + name + " for " + agent
}

// explainActions lists the actions that apply to f, in a fixed order, each
// with the exact request that performs it. Recommended marks the one the
// advisor suggested.
func (a *API) explainActions(f model.Flag, ex *model.FlagExplain, env *explainEnv) []model.ExplainAction {
	acts := []model.ExplainAction{}
	agent := f.Agent
	title := humanFlagTitle(f.Rule)

	var hosts []model.ExplainEgress
	seenHost := map[string]bool{}
	for _, eg := range ex.Egress {
		if !seenHost[eg.Host] {
			seenHost[eg.Host] = true
			hosts = append(hosts, eg)
		}
	}
	if a.allowlist != nil && agent != "" {
		for _, eg := range hosts {
			if eg.Allowlisted || !validAllowlistHost(eg.Host) {
				continue
			}
			name := eg.Host
			if eg.Org != "" && eg.Org != eg.Host {
				name += " (" + eg.Org + ")"
			}
			acts = append(acts, model.ExplainAction{
				ID: "allow-host", Label: allowHostLabel(name, eg.Host, eg.Org, agent),
				Consequence: "Future connections from " + agent + " to " + eg.Host + " are trusted and stop being flagged.",
				Method:      http.MethodPost, Path: "/allowlist",
				Body: map[string]any{"agent": agent, "host": eg.Host},
			})
		}
	}
	if s := ex.Subject; s != nil && a.guardBroker != nil && guardTokenRE.MatchString(agent) && strings.HasPrefix(s.Path, "/") {
		if rid := guardRuleForCategory[s.Category]; rid != "" {
			acts = append(acts, model.ExplainAction{
				ID: "allow-path", Label: "Always allow this file for " + agent,
				Consequence: agent + " may open " + s.Display + " without a guard prompt; other files under the " + rid + " rule still ask.",
				Method:      http.MethodPost, Path: "/guard/path-allow",
				Body: map[string]any{"agent": agent, "rule_id": rid, "path": s.Path},
			})
		}
	}
	if a.mutes != nil {
		for _, eg := range hosts {
			if !validMuteHost(eg.Host) {
				continue
			}
			if act, ok := muteRuleHostAction(f.Rule, title, eg.Host, agent); ok {
				acts = append(acts, act)
			}
			break
		}
		if act, ok := muteClassAction(f.Rule, title, agent); ok {
			acts = append(acts, act)
		}
	}
	if id, ok := a.store.IncidentIDForFlag(f.ID); ok {
		acts = append(acts, model.ExplainAction{
			ID: "open-incident", Label: "Open incident report",
			Consequence: "Shows the incident's remediation checklist with rotation advice; changes nothing.",
			Method:      http.MethodGet, Path: "/incidents?id=" + url.QueryEscape(id) + "&format=markdown",
		})
	}
	if !f.Acknowledged {
		acts = append(acts, model.ExplainAction{
			ID: "dismiss", Label: "Dismiss this flag",
			Consequence: "The flag is marked reviewed and stops counting as needing action; the rule keeps watching for the next one.",
			Method:      http.MethodPost, Path: "/flags/acknowledge",
			Body: map[string]any{"flag_id": f.ID},
		})
	}
	if ag, live := env.live[f.PID]; live && f.PID > 0 {
		body := map[string]any{"pid": f.PID}
		if ag.StartedAt != "" {
			body["started_at"] = ag.StartedAt
		}
		acts = append(acts, model.ExplainAction{
			ID: "kill", Label: fmt.Sprintf("Kill %s (pid %d)", firstNonEmpty([]string{agent, ag.Name, "agent"}), f.PID),
			Consequence: "The agent process tree is terminated now; unsaved work in it is lost.",
			Method:      http.MethodPost, Path: "/kill",
			Body: body,
		})
	}
	markRecommended(acts, f.Advisor)
	return acts
}

// recommendedFor maps the advisor's normalized suggested_action onto action
// ids, most specific first.
var recommendedFor = map[string][]string{
	"allow-host":         {"allow-host"},
	"mute-rule":          {"mute-rule-host", "mute-class"},
	"kill-agent":         {"kill"},
	"rotate-credentials": {"open-incident"},
}

func markRecommended(acts []model.ExplainAction, v *model.AdvisorVerdict) {
	if v == nil {
		return
	}
	for _, id := range recommendedFor[v.SuggestedAction] {
		for i := range acts {
			if acts[i].ID == id {
				acts[i].Recommended = true
				return
			}
		}
	}
}
