package injection

import (
	"regexp"
)

type Rule struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
}

var rules = []Rule{
	{
		Name:        "ignore-previous-instructions",
		Pattern:     regexp.MustCompile(`(?i)\b(ignore|disregard|forget|bypass)\s+(all\s+)?(previous|above|prior|system)\s+(instructions|directions|prompts|rules)\b`),
		Description: "Attempt to override system prompt and previous instructions",
	},
	{
		Name:        "system-prompt-override",
		Pattern:     regexp.MustCompile(`(?i)\b(you\s+are\s+now|new\s+system\s+instruction|system\s+prompt\s+override|act\s+as\s+an?\s+unrestricted)\b`),
		Description: "Attempt to reset or redefine system persona and constraints",
	},
	{
		Name:        "jailbreak-mode",
		Pattern:     regexp.MustCompile(`(?i)\b(DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled|jailbreak\s+enabled)\b`),
		Description: "Known jailbreak persona activation attempt",
	},
	{
		Name:        "secret-exfiltration-command",
		Pattern:     regexp.MustCompile(`(?i)\b(curl|wget|fetch|exfiltrate|post)\s+.*(https?://|webhook|\.env|id_rsa|keychain)\b`),
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
