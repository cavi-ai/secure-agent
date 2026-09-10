package injection

import (
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
)

type Rule struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
}

var rules = []Rule{
	{
		Name: "ignore-previous-instructions",
		// verb + optional determiner (the/your/all/any/these/those) + a
		// "priorness" word + a target noun (singular or plural). Catches the
		// canonical phrasings the narrow original missed: "ignore the previous
		// instructions", "ignore your previous instructions", "ignore all prior
		// guidelines", "disregard the above context", singular "instruction".
		Pattern:     regexp.MustCompile(`(?i)\b(ignore|disregard|forget|bypass|override)\s+(?:(?:all|any|the|your|these|those)\s+)?(previous|above|prior|earlier|preceding|system|initial|original|foregoing)\s+(instruction|direction|prompt|rule|guideline|policy|context|command)s?\b`),
		Description: "Attempt to override system prompt and previous instructions",
	},
	{
		Name:        "system-prompt-override",
		Pattern:     regexp.MustCompile(`(?i)\b(you\s+are\s+now|new\s+(system\s+)?(instruction|directive|rule|prompt)s?:|system\s+prompt\s+(override|bypass|injection)|act\s+as\s+an?\s+(unrestricted|unfiltered|uncensored))\b`),
		Description: "Attempt to reset or redefine system persona and constraints",
	},
	{
		Name:        "jailbreak-mode",
		Pattern:     regexp.MustCompile(`(?i)\b(DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+(enabled|on)|jailbreak(\s+(mode|enabled))?)\b`),
		Description: "Known jailbreak persona activation attempt",
	},
	{
		Name: "secret-exfiltration-command",
		// A fetch verb within 200 chars (same line) of an outbound target or a
		// secret path. Bounded and RE2-linear (no catastrophic backtracking).
		Pattern:     regexp.MustCompile(`(?i)\b(curl|wget|fetch|invoke-webrequest|nc|netcat)\b[^\n]{0,200}?(https?://|webhook|\.env\b|id_rsa|id_ed25519|\.aws/credentials|keychain)`),
		Description: "Prompt injection commanding outbound secret exfiltration",
	},
}

// Detect inspects text for prompt injection patterns and returns the rule name and match status.
func Detect(text string) (string, bool) {
	if text == "" {
		return "", false
	}

	for _, r := range rules {
		if r.Pattern.MatchString(text) {
			return r.Name, true
		}
	}
	return "", false
}

// snippetRadius bounds the excerpt around a match (chars each side).
const snippetRadius = 120

// DetectWithSnippet is Detect plus a bounded, redacted excerpt around the
// match — the operator (and the local advisor's second opinion) needs to see
// WHAT matched, not just that something did. The excerpt is scrubbed for
// credential shapes before it goes anywhere (the flagged page may itself
// carry secrets).
func DetectWithSnippet(text string) (string, string, bool) {
	if text == "" {
		return "", "", false
	}
	for _, r := range rules {
		if loc := r.Pattern.FindStringIndex(text); loc != nil {
			start := loc[0] - snippetRadius
			if start < 0 {
				start = 0
			}
			end := loc[1] + snippetRadius
			if end > len(text) {
				end = len(text)
			}
			snippet := strings.TrimSpace(text[start:end])
			snippet = strings.Join(strings.Fields(snippet), " ") // collapse whitespace runs
			return r.Name, redact.Scrub(snippet), true
		}
	}
	return "", "", false
}
