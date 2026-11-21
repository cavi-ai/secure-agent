package guard

import (
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// ConfirmFacts is the request a future-access confirmation names.
type ConfirmFacts struct {
	Agent      string
	Operation  string
	Resource   string
	Workspace  string
	Executable string
	Session    string
	RuleID     string
	Categories []string
}

// ButtonTerms is the sentence under a prompt's Allow button. It is empty
// for once, always, an unknown duration, and a kind permission with no kinds.
func ButtonTerms(ruleID string, categories []string, choice model.ScopeChoice) string {
	subject, ok := buttonSubject(ruleID, categories, choice.Category)
	if !ok {
		return ""
	}
	effect, ok := buttonEffect(subject, choice)
	if !ok {
		return ""
	}
	return effect + " Executable signatures are not verified. " + limitText(ruleID, choice.Category) + " Revoke under Protection → Rules & permissions."
}

// Confirm is the future-access dialog. Always names the verdict; every other
// duration says "allow" and the selected lifetime. Kind lists use the console
// join, with " and " between every label.
func Confirm(facts ConfirmFacts, verdict string, choice model.ScopeChoice) string {
	effect := confirmEffect(facts.RuleID, facts.Categories, choice)
	if choice.Kind == "always" {
		effect = verdict + " " + effect
	}
	return effect + ".\n\n" + confirmFacts(facts) + "\n\n" + confirmTail(facts.RuleID, choice.Category)
}

// Disclose attaches the button sentence and the confirmation effect and tail.
// Terms stays empty when ButtonTerms is empty.
func Disclose(ruleID string, categories []string, choice model.ScopeChoice) model.ScopeChoice {
	choice.Terms = ButtonTerms(ruleID, categories, choice)
	if choice.Kind == "once" {
		choice.Effect, choice.Tail = "", ""
		return choice
	}
	choice.Effect = confirmEffect(ruleID, categories, choice)
	choice.Tail = confirmTail(ruleID, choice.Category)
	return choice
}

func buttonSubject(ruleID string, categories []string, category bool) (string, bool) {
	if category {
		if len(categories) == 0 {
			return "", false
		}
		return "all " + joinSwift(kindLabels(categories)) + " from this tool in this workspace", true
	}
	if ruleID == model.EgressRule {
		return "these sends from this tool", true
	}
	return "this file and tool", true
}

func buttonEffect(subject string, choice model.ScopeChoice) (string, bool) {
	switch choice.Kind {
	case "session":
		return "Allows " + subject + " until this session ends.", true
	case "exact":
		switch choice.Expiry {
		case "24h":
			return "Allows " + subject + " for 24 hours.", true
		case "7d":
			return "Allows " + subject + " for 7 days.", true
		default:
			return "", false
		}
	case "standing":
		return "Allows " + subject + " until you revoke it.", true
	default:
		return "", false
	}
}

func confirmSubject(ruleID string, categories []string, category bool) string {
	if category {
		return "all " + strings.Join(kindLabels(categories), " and ") + " from this tool in this workspace"
	}
	if ruleID == model.EgressRule {
		return "these sends from this tool"
	}
	return "this file and tool"
}

func confirmDuration(choice model.ScopeChoice) string {
	switch choice.Kind {
	case "session":
		return "until this session ends"
	case "standing":
		return "until revoked"
	default:
		if choice.Expiry == "7d" {
			return "for 7 days"
		}
		return "for 24 hours"
	}
}

func confirmEffect(ruleID string, categories []string, choice model.ScopeChoice) string {
	if choice.Kind == "always" {
		rule := ruleID
		if rule == "" {
			rule = "unavailable"
		}
		return "every future path matched by rule " + rule
	}
	return "allow " + confirmSubject(ruleID, categories, choice.Category) + " " + confirmDuration(choice)
}

func confirmTail(ruleID string, category bool) string {
	return "Executable signatures are not verified. " + limitText(ruleID, category) + " Revoke under Protection → Rules & permissions."
}

func confirmFacts(facts ConfirmFacts) string {
	return "Agent: " + orUnknown(facts.Agent) + "\n" +
		"Operation: " + orUnknown(facts.Operation) + "\n" +
		"Resource: " + orUnknown(facts.Resource) + "\n" +
		"Workspace: " + orUnknown(facts.Workspace) + "\n" +
		"Executable path: " + orUnknown(facts.Executable) + "\n" +
		"Session: " + orUnknown(facts.Session)
}

func orUnknown(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

func limitText(ruleID string, category bool) string {
	if ruleID != model.EgressRule {
		return "File approval does not authorize network access."
	}
	if category {
		return "Other kinds of send still ask."
	}
	return "Other sends still ask."
}

func sendKindLabel(kind string) string {
	switch kind {
	case "git-push":
		return "git pushes"
	case "gh-write":
		return "GitHub writes (gh)"
	case "network-send":
		return "network sends"
	case "mcp-send":
		return "MCP sends"
	default:
		if strings.HasPrefix(kind, "mcp:") {
			return kind[len("mcp:"):] + " MCP sends"
		}
		return kind
	}
}

func kindLabels(categories []string) []string {
	labels := make([]string, len(categories))
	for i, category := range categories {
		labels[i] = sendKindLabel(category)
	}
	return labels
}

// joinSwift is "a", "a and b", or "a, b and c".
func joinSwift(labels []string) string {
	if len(labels) == 1 {
		return labels[0]
	}
	return strings.Join(labels[:len(labels)-1], ", ") + " and " + labels[len(labels)-1]
}
