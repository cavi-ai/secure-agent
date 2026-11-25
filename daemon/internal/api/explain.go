package api

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/report"
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

// Finding wording and mute helpers live in package report.
var (
	evidenceOfKind     = report.EvidenceOfKind
	firstNonEmpty      = report.FirstNonEmpty
	readerName         = report.ReaderName
	subjectEvidence    = report.SubjectEvidence
	explainSubject     = report.ExplainSubject
	displayPath        = report.DisplayPath
	splitHostPort      = report.SplitHostPort
	validMuteHost      = report.ValidMuteHost
	validMuteAgent     = report.ValidMuteAgent
	muteRuleHostAction = report.MuteRuleHostAction
	muteClassAction    = report.MuteClassAction
	muteAgentSuffix    = report.MuteAgentSuffix
)

// explainEnv is what an explanation reads besides the flag, resolved once
// per request so a list costs one status probe and one session read per
// session, not one per flag.
type explainEnv struct {
	home        string
	live        map[int32]AgentSummary
	sessions    map[string]*model.Session
	incidentIDs map[string]string
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
	if s, ok, err := a.store.GetSessionBounded(id); err == nil && ok {
		out = &s
	}
	env.sessions[id] = out
	return out
}

// lookupFlag reads one stored flag with its advisor verdict attached.
func (a *API) lookupFlag(id string) (model.Flag, bool) {
	f, found, _ := a.lookupFlagResult(id)
	return f, found
}

func (a *API) lookupFlagResult(id string) (model.Flag, bool, error) {
	f, found, err := a.store.GetFlag(id)
	if err != nil || !found {
		return f, found, err
	}
	v, ok, err := a.store.AdvisorVerdictResultFor(f.ID, "flag")
	if err != nil {
		return model.Flag{}, false, err
	}
	if ok {
		f.Advisor = &v
	}
	return f, true, nil
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
	f, ok, err := a.lookupFlagResult(parts[0])
	if err != nil {
		http.Error(w, "flag data unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		http.Error(w, "flag not found", http.StatusNotFound)
		return
	}
	f.Title = posture.HumanFlagTitle(f.Rule)
	f.Explain = a.explainFlag(f, true)
	writeJSON(w, f)
}

// stampExplains sets Explain on the first explainListCap flags, including
// reviewed history, without network lookups.
func (a *API) stampExplains(flags []model.Flag) {
	n := min(len(flags), explainListCap)
	if n == 0 {
		return
	}
	ids := make([]string, n)
	for i := range ids {
		ids[i] = flags[i].ID
	}
	env := a.newExplainEnv()
	env.incidentIDs, _ = a.store.IncidentIDsForFlags(ids)
	for i := 0; i < n; i++ {
		flags[i].Explain = a.explainFlagIn(flags[i], false, env)
	}
}

// explainFlag builds the plain-language reading of f. full permits one
// bounded reverse-DNS lookup per bare-IP destination; list stamping passes
// false and reads the identity tables and PTR cache only.
func (a *API) explainFlag(f model.Flag, full bool) *model.FlagExplain {
	return a.explainFlagIn(f, full, a.newExplainEnv())
}

func (a *API) explainFlagIn(f model.Flag, full bool, env *explainEnv) *model.FlagExplain {
	if env.incidentIDs == nil {
		env.incidentIDs = map[string]string{}
	}
	if _, seen := env.incidentIDs[f.ID]; !seen {
		links, _ := a.store.IncidentIDsForFlags([]string{f.ID})
		env.incidentIDs[f.ID] = links[f.ID]
	}
	assessment := model.AssessFinding(f)
	ex := &model.FlagExplain{Disposition: dispositionFor(f), Assessment: &assessment}
	sess := a.session(env, f.SessionID)
	workspace := f.Workspace
	if sess != nil && sess.Workspace != "" {
		workspace = sess.Workspace
	}
	subject := subjectEvidence(f.Evidence)
	var readTS time.Time
	if subject != nil {
		ex.Subject = explainSubject(*subject, workspace, report.RepoName(sess, workspace), env.home)
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
	ex.What = report.ExplainWhat(f, ex, sess)
	ex.Actions = a.explainActions(f, ex, env)
	pattern := flagEvidencePath(f)
	if pattern == "" {
		pattern = flagEvidenceHost(f)
	}
	if sum, err := a.store.LabelSummary(f.Agent, pattern, f.Rule); err == nil && sum.OK+sum.NotOK > 0 {
		ex.Labels = &sum
	}
	return ex
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
		id := hostid.IdentifyCached(host)
		if full {
			id = hostid.Identify(host)
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
// within explainContextWindow either side: the events nearest the anchor on
// each side, read through the session's time index.
func (a *API) nearestEvent(sessionID string, kind event.Kind, anchor time.Time) (event.Event, bool) {
	k := int(kind)
	at := anchor.UTC().Format(time.RFC3339)
	before, err := a.store.QueryEvents(store.EventFilter{Kind: &k, SessionID: sessionID, TimeSeek: true, Latest: true, Limit: 50,
		Since: anchor.Add(-explainContextWindow).UTC().Format(time.RFC3339), Until: at})
	if err != nil {
		return event.Event{}, false
	}
	after, err := a.store.QueryEvents(store.EventFilter{Kind: &k, SessionID: sessionID, TimeSeek: true, Limit: 50,
		Since: at, Until: anchor.Add(explainContextWindow).UTC().Format(time.RFC3339)})
	if err != nil {
		return event.Event{}, false
	}
	evs := append(before, after...)
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

// explainActions lists the actions that apply to f, in a fixed order, each
// with the exact request that performs it. Recommended marks the one the
// advisor suggested.
func (a *API) explainActions(f model.Flag, ex *model.FlagExplain, env *explainEnv) []model.ExplainAction {
	acts := []model.ExplainAction{}
	if a.sysAgent != nil {
		acts = append(acts, model.ExplainAction{ID: "review-local", Label: "Send to local agent review", Consequence: "The selected finding and recent local behavior metadata are reviewed by local Ollama. Its recommendation appears in the Agent review queue. No command or harness starts; execution requires your separate confirmation.", Method: http.MethodPost, Path: "/agent/analyze", Body: map[string]any{"flag_ids": []string{f.ID}}})
	}

	if act, ok := a.nonSecretFileAction(f); ok && !f.Acknowledged {
		acts = append(acts, act)
	}
	if act, ok := a.expectAction(f); ok && !f.Acknowledged {
		acts = append(acts, act)
	}
	if read := evidenceOfKind(f, "read"); read != nil && filepath.IsAbs(read.Label) {
		acts = append(acts, model.ExplainAction{ID: "inspect-file", Label: "Inspect file details", Consequence: "Shows file metadata, recorded accesses, and supported .env variable names without values; changes nothing.", Method: http.MethodGet, Path: "/files/detail", Body: map[string]any{"path": read.Label}})
	}
	agent := f.Agent
	title := posture.HumanFlagTitle(f.Rule)

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
				ID: "allow-host", Label: report.AllowHostLabel(name, eg.Host, eg.Org, agent),
				Consequence: "Future connections from " + agent + " to " + eg.Host + " are trusted and stop being flagged. This finding is marked reviewed.",
				Method:      http.MethodPost, Path: "/allowlist",
				Body: map[string]any{"agent": agent, "host": eg.Host},
			})
		}
	}
	if s := ex.Subject; s != nil && a.guardBroker != nil && guardTokenRE.MatchString(agent) && strings.HasPrefix(s.Path, "/") {
		if rid := report.GuardRuleForCategory[s.Category]; rid != "" && !a.store.GuardPathAllowed(agent, rid, s.Path) {
			acts = append(acts, model.ExplainAction{
				ID: "allow-path", Label: "Always allow this file for " + agent,
				Consequence: agent + " may open " + s.Display + " without a guard prompt; other files under the " + rid + " rule still ask. This finding is marked reviewed; new suspicious behavior is still monitored.",
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
	if id := env.incidentIDs[f.ID]; id != "" {
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
	report.MarkRecommended(acts, f.Advisor)
	return acts
}
