package api

import (
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Patterns: every flag one agent raised under one rule on one subject in a
// window is one pattern, served with its cadence, identity and actions. The
// grouping reads stored flags only; it never depends on the correlator's
// repeat suppression.
const (
	patternDefaultMin = 3
	patternMaxHours   = 720
	patternFlagLimit  = 5000
	patternBurstGap   = 5 * time.Second
)

// handlePatterns serves GET /patterns?hours=&min=: the patterns of the last
// hours (1..720, default 24) with at least min flags (>= 2, default 3).
func (a *API) handlePatterns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	hours := queryInt(q.Get("hours"), 24)
	minCount := queryInt(q.Get("min"), patternDefaultMin)
	if hours < 1 || hours > patternMaxHours || minCount < 2 {
		http.Error(w, fmt.Sprintf("hours must be 1..%d and min at least 2", patternMaxHours), http.StatusBadRequest)
		return
	}
	writeJSON(w, a.computePatterns(time.Now().Add(-time.Duration(hours)*time.Hour), minCount))
}

// computePatterns groups the flags raised since `since` by agent, rule and
// served subject, keeps groups of at least min flags, most open first.
func (a *API) computePatterns(since time.Time, min int) []model.Pattern {
	flags := a.store.QueryFlags(store.FlagFilter{Since: since.UTC().Format(time.RFC3339), Limit: patternFlagLimit})
	return a.patternsOf(flags, since, time.Now(), min)
}

func (a *API) patternsOf(flags []model.Flag, since, now time.Time, minCount int) []model.Pattern {
	type group struct {
		p     model.Pattern
		flags []model.Flag
	}
	byKey := map[string]*group{}
	var keys []string
	home := strings.TrimRight(explainHome(), "/")
	for _, f := range flags {
		subject, subjectKey := patternSubject(f, home)
		key := f.Agent + "|" + f.Rule + "|" + subjectKey
		g, ok := byKey[key]
		if !ok {
			g = &group{p: model.Pattern{Key: key, Agent: f.Agent, Rule: f.Rule, Title: humanFlagTitle(f.Rule), Subject: subject}}
			byKey[key] = g
			keys = append(keys, key)
		}
		g.flags = append(g.flags, f)
	}
	out := []model.Pattern{}
	var env *explainEnv
	for _, key := range keys {
		g := byKey[key]
		if len(g.flags) < minCount {
			continue
		}
		if env == nil {
			env = a.newExplainEnv()
		}
		out = append(out, a.fillPattern(g.p, g.flags, since, now, env))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Unacked != out[j].Unacked {
			return out[i].Unacked > out[j].Unacked
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// patternSubject is the served subject of f and the text that keys it: the
// file the explanation names (display path; the absolute path keys it), else
// the first destination host, else nothing.
func patternSubject(f model.Flag, home string) (model.EvidenceItem, string) {
	if ev := subjectEvidence(f.Evidence); ev != nil {
		s := explainSubject(*ev, f.Workspace, "", home)
		return model.EvidenceItem{Kind: ev.Kind, Label: s.Display, Sub: s.CategoryLabel}, s.Path
	}
	for _, ev := range f.Evidence {
		if ev.Kind != "connect" || ev.Label == "" {
			continue
		}
		if host, _ := splitHostPort(ev.Label); host != "" {
			return model.EvidenceItem{Kind: "connect", Label: host, Sub: correlate.IdentifyCached(host).Org}, host
		}
	}
	return model.EvidenceItem{}, ""
}

func (a *API) fillPattern(p model.Pattern, flags []model.Flag, since, now time.Time, env *explainEnv) model.Pattern {
	sorted := append([]model.Flag(nil), flags...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TS.Before(sorted[j].TS) })
	p.Count = len(sorted)
	p.First, p.Last = sorted[0].TS, sorted[len(sorted)-1].TS

	gaps := make([]float64, 0, len(sorted))
	for i := 1; i < len(sorted); i++ {
		gap := sorted[i].TS.Sub(sorted[i-1].TS)
		gaps = append(gaps, gap.Seconds())
		if gap < patternBurstGap {
			p.Bursts++
		}
	}
	p.MedianGapS = median(gaps)
	p.Cadence = cadencePhrase(p.MedianGapS, len(gaps))

	width := now.Sub(since) / 24
	for _, f := range sorted {
		i := 0
		if width > 0 {
			i = int(f.TS.Sub(since) / width)
		}
		p.Hourly[max(0, min(23, i))]++
	}

	pidN := map[int32]int{}
	sessionN := map[string]int{}
	var open, closed []string
	worst, worstRank := model.Disposition{}, 0
	for i := len(sorted) - 1; i >= 0; i-- {
		f := sorted[i]
		if f.PID > 0 {
			pidN[f.PID]++
		}
		if f.SessionID != "" {
			sessionN[f.SessionID]++
		}
		if f.Acknowledged {
			closed = append(closed, f.ID)
			continue
		}
		open = append(open, f.ID)
		if d := dispositionFor(f); dispositionRank(d.State) > worstRank {
			worst, worstRank = d, dispositionRank(d.State)
		}
	}
	p.Unacked = len(open)
	p.PIDs, p.PIDCount = busiest(pidN), len(pidN)
	p.Sessions, p.SessionCount = busiest(sessionN), len(sessionN)
	ids := make([]string, 0, len(open)+len(closed))
	p.FlagIDs = capList(append(append(ids, open...), closed...), model.PatternFlagIDCap)
	if p.Unacked == 0 {
		p.Disposition = model.Disposition{State: model.DispositionAcknowledged, Text: "Reviewed", Why: p.Title}
	} else {
		p.Disposition = worst
	}
	p.Summary = patternSummary(p, now)
	p.Actions = a.patternActions(p, capList(open, model.PatternFlagIDCap), env)
	return p
}

// dispositionRank orders open dispositions: critical > warning > benign-likely.
func dispositionRank(state string) int {
	switch state {
	case model.DispositionCritical:
		return 3
	case model.DispositionWarning:
		return 2
	case model.DispositionBenignLikely:
		return 1
	}
	return 0
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	s := append([]float64(nil), values...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// busiest lists the most frequent keys first (ties by key), at most
// model.PatternListCap.
func busiest[K int32 | string](counts map[K]int) []K {
	keys := make([]K, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return capList(keys, model.PatternListCap)
}

func capList[T any](list []T, n int) []T {
	if len(list) > n {
		return list[:n]
	}
	return list
}

// cadencePhrase reads the median gap between consecutive flags.
func cadencePhrase(medianS float64, gaps int) string {
	every := func(n int, unit string) string {
		if n <= 1 {
			return "about every " + unit
		}
		return fmt.Sprintf("about every %d %ss", n, unit)
	}
	switch {
	case gaps == 0:
		return "once"
	case medianS < 1:
		return "in bursts under a second apart"
	case medianS < patternBurstGap.Seconds():
		return "in bursts a few seconds apart"
	case medianS < 90:
		return every(int(math.Round(medianS)), "second")
	case medianS < 90*60:
		return every(int(math.Round(medianS/60)), "minute")
	default:
		return every(int(math.Round(medianS/3600)), "hour")
	}
}

// patternVerb is the rule's action phrase from the rule-title table's
// vocabulary: "<agent> <verb> <n> times".
func patternVerb(rule string, subject model.EvidenceItem) string {
	host := ""
	if subject.Kind == "connect" {
		host = subject.Label
	}
	switch rule {
	case "keychain-access":
		return "touched the " + keychainName(subject.Label)
	case "keychain-security-cli":
		return "ran the macOS keychain tool"
	case "tcc-tamper":
		return "changed macOS privacy permissions"
	case "sensitive-read-then-connect":
		if subject.Label != "" && host == "" {
			return "read " + subject.Label + " and connected out"
		}
		return "read a secret and connected out"
	case "proxy-secret-leak":
		return "sent a secret to " + firstNonEmpty([]string{host, "an outside host"})
	case "proxy-prompt-injection":
		return "received a prompt injection from " + firstNonEmpty([]string{host, "an outside host"})
	case "secret-in-transcript":
		return "wrote a secret into its transcript"
	default:
		return "raised \"" + humanFlagTitle(rule) + "\""
	}
}

// keychainName: ".../login.keychain-db" → "login keychain".
func keychainName(path string) string {
	name := filepath.Base(path)
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".keychain-db"), ".keychain")
	if path == "" || name == "" || name == "." || name == "/" {
		return "keychain"
	}
	return name + " keychain"
}

// patternWindow: "between 03:00 and 03:08" (local time), with the date when
// the window is not today or spans days.
func patternWindow(first, last, now time.Time) string {
	f, l := first.Local(), last.Local()
	day := func(t time.Time) string { return t.Format("2006-01-02") }
	switch {
	case day(f) != day(l):
		return "between " + f.Format("Jan 2 15:04") + " and " + l.Format("Jan 2 15:04")
	case day(l) != day(now.Local()):
		return "on " + f.Format("Jan 2") + " between " + f.Format("15:04") + " and " + l.Format("15:04")
	default:
		return "between " + f.Format("15:04") + " and " + l.Format("15:04")
	}
}

// patternSummary is the one served sentence: who did what how many times,
// when, from how many processes and sessions, and how often. No flag ids.
func patternSummary(p model.Pattern, now time.Time) string {
	var ident []string
	if p.PIDCount > 0 {
		noun := "processes"
		if p.PIDCount == 1 {
			noun = "process"
		}
		ident = append(ident, fmt.Sprintf("%d %s", p.PIDCount, noun))
	}
	if p.SessionCount > 0 {
		ident = append(ident, fmt.Sprintf("%d session%s", p.SessionCount, plural(p.SessionCount)))
	}
	who := firstNonEmpty([]string{p.Agent, "An agent"})
	s := fmt.Sprintf("%s %s %d times %s", who, patternVerb(p.Rule, p.Subject), p.Count, patternWindow(p.First, p.Last, now))
	if len(ident) > 0 {
		s += " (" + strings.Join(ident, ", ") + ")"
	}
	return s + ", " + p.Cadence + "."
}

// patternActions: the explainActions shapes for a whole pattern — allow the
// host (egress rules), mute, dismiss every open flag in one request, kill a
// live process. The recommended one follows the disposition: benign-likely
// → allow or mute; critical → kill.
func (a *API) patternActions(p model.Pattern, openIDs []string, env *explainEnv) []model.ExplainAction {
	acts := []model.ExplainAction{}
	host := ""
	if p.Subject.Kind == "connect" {
		host = p.Subject.Label
	}
	if host != "" && a.allowlist != nil && p.Agent != "" && validAllowlistHost(host) && !a.allowlist.Allows(p.Agent, host) {
		acts = append(acts, model.ExplainAction{
			ID: "allow-host", Label: "Allow " + host + " for " + p.Agent,
			Consequence: "Future connections from " + p.Agent + " to " + host + " are trusted and stop being flagged; this pattern's open flags are marked reviewed.",
			Method:      http.MethodPost, Path: "/allowlist",
			Body: map[string]any{"agent": p.Agent, "host": host},
		})
	}
	if a.mutes != nil {
		if host != "" && validMuteHost(host) {
			acts = append(acts, muteRuleHostAction(p.Rule, p.Title, host, p.Agent))
		} else if act, ok := muteClassAction(p.Rule, p.Title, p.Agent); ok {
			acts = append(acts, act)
		}
	}
	if len(openIDs) > 0 {
		label := fmt.Sprintf("Dismiss all %d open", len(openIDs))
		if len(openIDs) < p.Unacked {
			label = fmt.Sprintf("Dismiss the newest %d open", len(openIDs))
		}
		acts = append(acts, model.ExplainAction{
			ID: "dismiss-all", Label: label,
			Consequence: "These flags are marked reviewed and stop counting as needing action; the rule keeps watching for the next one.",
			Method:      http.MethodPost, Path: "/flags/acknowledge",
			Body: map[string]any{"flag_ids": openIDs},
		})
	}
	for _, pid := range p.PIDs {
		ag, live := env.live[pid]
		if !live {
			continue
		}
		body := map[string]any{"pid": pid}
		if ag.StartedAt != "" {
			body["started_at"] = ag.StartedAt
		}
		acts = append(acts, model.ExplainAction{
			ID: "kill", Label: fmt.Sprintf("Kill %s (pid %d)", firstNonEmpty([]string{p.Agent, ag.Name, "agent"}), pid),
			Consequence: "The agent process tree is terminated now; unsaved work in it is lost.",
			Method:      http.MethodPost, Path: "/kill",
			Body: body,
		})
		break
	}
	var prefer []string
	switch p.Disposition.State {
	case model.DispositionBenignLikely:
		prefer = []string{"allow-host", "mute-rule-host", "mute-class"}
	case model.DispositionCritical:
		prefer = []string{"kill"}
	}
	for _, id := range prefer {
		if i := actionIndex(acts, id); i >= 0 {
			acts[i].Recommended = true
			break
		}
	}
	return acts
}

func actionIndex(acts []model.ExplainAction, id string) int {
	for i := range acts {
		if acts[i].ID == id {
			return i
		}
	}
	return -1
}
