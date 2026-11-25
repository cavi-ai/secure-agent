package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/pattern"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/report"
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
	patterns, err := a.computePatternsResult(time.Now().Add(-time.Duration(hours)*time.Hour), minCount)
	if err != nil {
		http.Error(w, "flag data unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, patterns)
}

// computePatternsResult groups the flags raised since `since` by agent, rule
// and served subject, keeps groups of at least min flags, most open first.
func (a *API) computePatternsResult(since time.Time, min int) ([]model.Pattern, error) {
	flags, err := a.flagReads.read(a.store, store.FlagFilter{Since: since.UTC().Format(time.RFC3339), Limit: patternFlagLimit})
	if err != nil {
		return nil, err
	}
	return a.patternsOf(flags, since, time.Now(), min), nil
}

func (a *API) patternsOf(flags []model.Flag, since, now time.Time, minCount int) []model.Pattern {
	type group struct {
		p           model.Pattern
		flags       []model.Flag
		occurrences int // flags plus the repeats folded into them
	}
	byKey := map[string]*group{}
	var keys []string
	home := strings.TrimRight(explainHome(), "/")
	for _, f := range flags {
		subject, subjectKey := pattern.Subject(f, home)
		key := f.Agent + "|" + f.Rule + "|" + subjectKey
		g, ok := byKey[key]
		if !ok {
			g = &group{p: model.Pattern{Key: key, Agent: f.Agent, Rule: f.Rule, Title: posture.HumanFlagTitle(f.Rule), Subject: subject}}
			byKey[key] = g
			keys = append(keys, key)
		}
		g.flags = append(g.flags, f)
		g.occurrences += 1 + f.Repeats
	}
	out := []model.Pattern{}
	var env *explainEnv
	for _, key := range keys {
		g := byKey[key]
		if g.occurrences < minCount {
			continue
		}
		if env == nil {
			env = a.newExplainEnv()
		}
		out = append(out, a.fillPattern(g.p, g.flags, since, now, env))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if x, y := pattern.DispositionRank(out[i].Disposition.State), pattern.DispositionRank(out[j].Disposition.State); x != y {
			return x > y
		}
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

func (a *API) fillPattern(p model.Pattern, flags []model.Flag, since, now time.Time, env *explainEnv) model.Pattern {
	sorted := append([]model.Flag(nil), flags...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TS.Before(sorted[j].TS) })
	p.First, p.Last = sorted[0].TS, sorted[len(sorted)-1].TS
	repeats := 0
	for _, f := range sorted {
		repeats += f.Repeats
		if f.LastSeen != nil && f.LastSeen.After(p.Last) {
			p.Last = *f.LastSeen
		}
	}
	p.Count = len(sorted) + repeats

	gaps := make([]float64, 0, len(sorted))
	for i := 1; i < len(sorted); i++ {
		gap := sorted[i].TS.Sub(sorted[i-1].TS)
		gaps = append(gaps, gap.Seconds())
		if gap < pattern.BurstGap {
			p.Bursts++
		}
	}
	p.MedianGapS = pattern.Median(gaps)
	if repeats > 0 {
		// Folded repeats carry no times of their own: the cadence is the
		// span over the occurrences.
		p.MedianGapS = p.Last.Sub(p.First).Seconds() / float64(p.Count-1)
	}
	p.Cadence = pattern.CadencePhrase(p.MedianGapS, p.Count-1)

	width := now.Sub(since) / 24
	for _, f := range sorted {
		i := 0
		if width > 0 {
			i = int(f.TS.Sub(since) / width)
		}
		p.Hourly[max(0, min(23, i))] += 1 + f.Repeats
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
		if d := dispositionFor(f); pattern.DispositionRank(d.State) > worstRank {
			worst, worstRank = d, pattern.DispositionRank(d.State)
		}
	}
	p.Unacked = len(open)
	p.Assessment = model.StrongestFindingAssessment(sorted)
	p.PIDs, p.PIDCount = pattern.Busiest(pidN), len(pidN)
	p.Sessions, p.SessionCount = pattern.Busiest(sessionN), len(sessionN)
	p.Processes = pattern.Processes(sorted)
	p.Flags = len(sorted)
	if p.Rule == readConnectRule {
		p.Destinations = pattern.Destinations(sorted)
	}
	ids := make([]string, 0, len(open)+len(closed))
	p.FlagIDs = pattern.CapList(append(append(ids, open...), closed...), model.PatternFlagIDCap)
	if p.Unacked == 0 {
		p.Disposition = model.Disposition{State: model.DispositionAcknowledged, Text: "Reviewed", Why: p.Title}
	} else {
		p.Disposition = worst
	}
	p.Summary = pattern.Summary(p, now, pattern.Reader(sorted))
	p.Actions = a.patternActions(p, pattern.CapList(open, model.PatternFlagIDCap), env)
	if len(open) > 0 {
		// open is newest first: the newest open flag names the pattern.
		for _, f := range sorted {
			if f.ID == open[0] {
				if a.sysAgent != nil {
					p.Actions = append(p.Actions, model.ExplainAction{ID: "review-local", Label: "Send to local agent review", Consequence: "Review the selected finding through local Ollama; no command or harness starts.", Method: http.MethodPost, Path: "/agent/analyze", Body: map[string]any{"flag_ids": []string{f.ID}}})
				}
				if read := report.EvidenceOfKind(f, "read"); read != nil {
					p.Actions = append(p.Actions, model.ExplainAction{ID: "inspect-file", Label: "Inspect file details", Consequence: "Shows file metadata and supported .env variable names without values; changes nothing.", Method: http.MethodGet, Path: "/files/detail", Body: map[string]any{"path": read.Label}})
				}
				if act, ok := a.nonSecretFileAction(f); ok {
					p.Actions = append(p.Actions, act)
				}
				if act, ok := a.expectAction(f); ok {
					p.Actions = append([]model.ExplainAction{act}, p.Actions...)
				}
				break
			}
		}
	}
	return p
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
		if host != "" && report.ValidMuteHost(host) {
			if act, ok := report.MuteRuleHostAction(p.Rule, p.Title, host, p.Agent); ok {
				acts = append(acts, act)
			}
		} else if act, ok := report.MuteClassAction(p.Rule, p.Title, p.Agent); ok {
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
			ID: "kill", Label: fmt.Sprintf("Kill %s (pid %d)", report.FirstNonEmpty([]string{p.Agent, ag.Name, "agent"}), pid),
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
		if i := pattern.ActionIndex(acts, id); i >= 0 {
			acts[i].Recommended = true
			break
		}
	}
	return acts
}
