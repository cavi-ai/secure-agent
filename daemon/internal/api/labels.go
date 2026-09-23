package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Label bounds: similar labels shown and sent to the model, consistent
// labels before a suggestion, reason length.
const (
	labelSimilarLimit = 5
	labelSuggestAfter = 3
	labelReasonMax    = 200
)

// flagEvidenceHost is the host of a flag's first connect evidence item.
func flagEvidenceHost(f model.Flag) string {
	for _, ev := range f.Evidence {
		if ev.Kind != "connect" || ev.Label == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(ev.Label); err == nil {
			return h
		}
		return ev.Label
	}
	return ""
}

// labelKeys are the rule, agent and pattern (the evidence path, else the
// destination host) a subject's labels are keyed by.
func labelKeys(t planTarget) (rule, agent, pattern string) {
	pattern = t.path
	if pattern == "" && t.flag != nil {
		pattern = flagEvidenceHost(*t.flag)
	}
	return t.rule, t.agent, pattern
}

func (a *API) recordLabel(l model.OperatorLabel) {
	if l.Pattern == "" && l.Rule == "" {
		return
	}
	l.CreatedAt = time.Now()
	a.store.PutOperatorLabel(l)
}

// handleLabels serves POST /labels {subject, label, reason, source}: an
// explicit Mark ok / Mark not ok, or the console's record of a kill.
func (a *API) handleLabels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Subject string `json:"subject"`
		Label   string `json:"label"`
		Reason  string `json:"reason"`
		Source  string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `body must be {"subject","label":"ok|not_ok","reason","source":"mark|kill"}`, http.StatusBadRequest)
		return
	}
	if req.Source == "" {
		req.Source = "mark"
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if (req.Label != "ok" && req.Label != "not_ok") || (req.Source != "mark" && req.Source != "kill") ||
		utf8.RuneCountInString(req.Reason) > labelReasonMax {
		http.Error(w, fmt.Sprintf("label must be ok or not_ok, source mark or kill, reason at most %d characters", labelReasonMax), http.StatusBadRequest)
		return
	}
	t, ok := a.resolvePlanTarget(req.Subject)
	if !ok {
		http.Error(w, "no stored flag, incident or evidence file matches this subject", http.StatusNotFound)
		return
	}
	rule, agent, pattern := labelKeys(t)
	a.recordLabel(model.OperatorLabel{Kind: t.kind, Rule: rule, Agent: agent, Pattern: pattern,
		Label: req.Label, Reason: req.Reason, Source: req.Source})
	writeJSON(w, map[string]string{"status": "ok"})
}

// labelContext is what the operator decided before about cases like t, and
// the suggestion consistent labels earn: ok → the offered allow action; not
// ok → the offered kill, and the playbook's guard rule.
func (a *API) labelContext(t planTarget, offered []string) *model.LabelContext {
	rule, agent, pattern := labelKeys(t)
	ctx := &model.LabelContext{
		Summary: a.store.LabelSummary(agent, pattern, rule),
		Similar: a.store.SimilarLabels(rule, agent, pattern, labelSimilarLimit),
	}
	sum := ctx.Summary
	who := agent
	if who == "" {
		who = "this agent"
	}
	switch {
	case sum.OK >= labelSuggestAfter && sum.NotOK == 0:
		s := &model.LabelSuggestion{Label: "ok", Text: fmt.Sprintf("You marked this %d times as routine for %s.", sum.OK, who)}
		for _, id := range []string{"allow-path", "allow-host"} {
			if slices.Contains(offered, id) {
				s.ActionID = id
				s.Text += " Allow it so it stops flagging."
				break
			}
		}
		ctx.Suggestion = s
	case sum.NotOK >= labelSuggestAfter && sum.OK == 0:
		s := &model.LabelSuggestion{Label: "not_ok", Text: fmt.Sprintf("You marked this %d times as not ok for %s. Add the playbook's guard rule so it is stopped before it happens.", sum.NotOK, who)}
		if slices.Contains(offered, "kill") {
			s.ActionID = "kill"
		}
		ctx.Suggestion = s
	}
	return ctx
}

// labelLines renders similar labels for the plan context.
func labelLines(labels []model.OperatorLabel, now time.Time) []string {
	var out []string
	for _, l := range labels {
		line := fmt.Sprintf("operator label: %s (%s, %s ago) rule %q agent %q on %q", l.Label, l.Source,
			now.Sub(l.CreatedAt).Round(time.Minute), l.Rule, l.Agent, l.Pattern)
		if l.Reason != "" {
			line += ": " + l.Reason
		}
		out = append(out, line)
	}
	return out
}
