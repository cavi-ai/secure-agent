package redact

import (
	"regexp"
)

// The rules mirror plugin/hooks/activity_log.py; testdata/cases.json is the
// contract both implementations must satisfy.

type patternRule struct {
	name string
	re   *regexp.Regexp
	repl string
}

// PrivateKeys removes the entire PEM envelope, rather than only the marker
// used to detect it. An unterminated envelope withholds the remaining text.
var privateKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)`)

func PrivateKeys(s string) string {
	return privateKeyRE.ReplaceAllLiteralString(s, "[REDACTED:private-key]")
}

// contextRules mask values identified by what precedes them: a password
// flag, a credential-named assignment, or URL userinfo. They run after the
// token rules so "token: Bearer <value>" masks the value, not the word. A
// value starting with "[" is an existing mask, such as the firewall's
// [REDACTED:<pattern id>], and keeps its label.
var contextRules = []patternRule{
	{
		re:   regexp.MustCompile(`(?i)(\s-w|\s--?password(?:-phrase)?)\s+('[^']*'|"[^"]*"|[^\s\[]\S*)`),
		repl: "${1} [REDACTED]",
	},
	{
		re:   regexp.MustCompile(`(?i)\b((?:password|passwd|secret|token|api[_-]?key|aws_secret_access_key)\w*\s*[:=]\s*)('[^']*'|"[^"]*"|[^\s\[]\S*)`),
		repl: "${1}[REDACTED]",
	},
	{
		re:   regexp.MustCompile(`://[^/\s:@]+:[^@\s/\[][^@\s/]*@`),
		repl: "://[REDACTED]@",
	},
}

// tokenRules match credentials by their own shape.
var tokenRules = []patternRule{
	{
		name: "bearer-token",
		re:   regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`),
		repl: "Bearer [REDACTED]",
	},
	{
		name: "jwt-token",
		re:   regexp.MustCompile(`\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b`),
		repl: "[REDACTED]",
	},
	{
		name: "aws-access-key",
		re:   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		repl: "[REDACTED]",
	},
	{
		name: "provider-key",
		re:   regexp.MustCompile(`\bsk-[A-Za-z0-9\-_]{16,}\b`),
		repl: "[REDACTED]",
	},
	{
		name: "github-token",
		re:   regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}\b`),
		repl: "[REDACTED]",
	},
	{
		name: "gitlab-token",
		re:   regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{16,}\b`),
		repl: "[REDACTED]",
	},
	{
		name: "slack-token",
		re:   regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
		repl: "[REDACTED]",
	},
}

func Scrub(s string) string {
	res := PrivateKeys(s)
	for _, r := range tokenRules {
		res = r.re.ReplaceAllString(res, r.repl)
	}
	for _, r := range contextRules {
		res = r.re.ReplaceAllString(res, r.repl)
	}
	return res
}

// Detect names the first credential shape in s. Context rules are not
// consulted: a credential-named key alone is not evidence of a secret.
func Detect(s string) (string, bool) {
	for _, r := range tokenRules {
		if r.re.MatchString(s) {
			return r.name, true
		}
	}
	return "", false
}
