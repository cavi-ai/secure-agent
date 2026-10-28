package model

import "strings"

// UntrustedEgress is the guard hook's account of a send from a session that
// earlier read untrusted content: what the session read (and who sent it, as
// far as the machine records it), what it sent through, and the decision.
// Every field is hook-supplied text; Clean bounds it before it is trusted for
// display.
type UntrustedEgress struct {
	Decision string           `json:"decision"`
	Sinks    string           `json:"sinks"`
	Harness  string           `json:"harness,omitempty"`
	Sources  []UntrustedInput `json:"sources"`
}

// UntrustedInput is one untrusted input the session read.
type UntrustedInput struct {
	TS       string `json:"ts,omitempty"`
	Kind     string `json:"kind"`
	Tool     string `json:"tool,omitempty"`
	Location string `json:"location"`
	Origin   string `json:"origin,omitempty"`
}

// Bounds on hook-supplied text.
const (
	UntrustedMaxSources = 8
	untrustedFieldMax   = 300
	untrustedSinksMax   = 500
	untrustedShortMax   = 120
)

// untrustedDecisions: the guard's decision on the send, as evidence states it.
var untrustedDecisions = map[string]string{
	"monitored": "ran; monitor mode records it",
	"asked":     "the harness asked you",
	"allowed":   "you allowed it",
	"denied":    "blocked",
}

// UntrustedDecisionLabel is the display text of a guard decision.
func UntrustedDecisionLabel(decision string) string { return untrustedDecisions[decision] }

var untrustedKinds = map[string]string{
	"image":  "Image",
	"web":    "Web page",
	"search": "Web search",
	"mcp":    "MCP tool output",
	"fetch":  "Downloaded content",
	"gh":     "GitHub content",
}

// UntrustedKindLabel is the display name of an input kind.
func UntrustedKindLabel(kind string) string {
	if label, ok := untrustedKinds[kind]; ok {
		return label
	}
	return "Untrusted input"
}

// Clean returns the record with every field bounded and stripped of control
// characters, or false when it names no known decision, no sink or no input.
func (u UntrustedEgress) Clean() (UntrustedEgress, bool) {
	out := UntrustedEgress{
		Decision: u.Decision,
		Sinks:    clip(u.Sinks, untrustedSinksMax),
		Harness:  clip(u.Harness, untrustedShortMax),
	}
	if _, ok := untrustedDecisions[out.Decision]; !ok || out.Sinks == "" {
		return UntrustedEgress{}, false
	}
	for _, s := range u.Sources {
		if len(out.Sources) == UntrustedMaxSources {
			break
		}
		in := UntrustedInput{
			TS:       clip(s.TS, untrustedShortMax),
			Kind:     clip(s.Kind, untrustedShortMax),
			Tool:     clip(s.Tool, untrustedShortMax),
			Location: clip(s.Location, untrustedFieldMax),
			Origin:   clip(s.Origin, untrustedFieldMax),
		}
		if in.Kind == "" && in.Location == "" {
			continue
		}
		out.Sources = append(out.Sources, in)
	}
	if len(out.Sources) == 0 {
		return UntrustedEgress{}, false
	}
	return out, true
}

// assessUntrustedEgress: a send after untrusted input is a lead for review. It
// does not establish that the content steered the send or what data left.
func assessUntrustedEgress(f Flag, a FindingAssessment) FindingAssessment {
	inputs := 0
	var send *EvidenceItem
	for i := range f.Evidence {
		switch f.Evidence[i].Kind {
		case "untrusted-input":
			inputs++
		case "send":
			send = &f.Evidence[i]
		}
	}
	if inputs == 0 || send == nil {
		return a
	}
	a.EvidenceBasis = []string{"guard-hook-record"}
	a.Risk, a.ResidualRisk, a.Control = "review", "possible-exposure", "observed-only"
	switch send.Rule {
	case "denied":
		a.Control, a.ResidualRisk = "blocked", "none-established"
	case "allowed":
		a.Control = "allowed"
	}
	a.Reason = "This session read content from outside your instructions, then sent data out. Text in images, web pages and tool output can carry instructions an agent follows."
	a.Limits = []string{
		"The guard matches sends by command name and shape; it does not establish that the untrusted content caused the send or what data left.",
		"Origins are what git and macOS recorded for the input; they can be missing or rewritten.",
	}
	return a
}

func clip(s string, max int) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }), " ")
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
