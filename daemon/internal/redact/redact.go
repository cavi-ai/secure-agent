package redact

import (
	"regexp"
	"strings"
)

// The rules mirror plugin/hooks/activity_log.py; testdata/cases.json is the
// contract both implementations must satisfy.

type patternRule struct {
	name string
	re   *regexp.Regexp
	repl string
	// detect, when set, replaces re for Detect: a stricter shape for naming
	// a hit than for masking one.
	detect *regexp.Regexp
	// keep leaves a match unmasked when its last capture group, the value,
	// satisfies it.
	keep func(value string) bool
}

// PrivateKeys removes the entire PEM envelope, rather than only the marker
// used to detect it. An unterminated envelope withholds the remaining text.
var privateKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)`)

func PrivateKeys(s string) string {
	return privateKeyRE.ReplaceAllLiteralString(s, "[REDACTED:private-key]")
}

// maskRE is an existing mask, such as the firewall's [REDACTED:<pattern id>],
// optionally quoted and followed only by punctuation (`"}` in JSON). A
// context rule keeps it and its label.
var maskRE = regexp.MustCompile(`^['"]?\[REDACTED(?::[^\]\s]*)?\][^A-Za-z0-9]*$`)

func isMask(v string) bool { return maskRE.MatchString(v) }

// portPathRE is "port/path" after a host and colon: no userinfo.
var portPathRE = regexp.MustCompile(`^[0-9]+/`)

// contextRules mask values identified by what precedes them: a keychain
// password flag, a password flag, a credential-named assignment, or URL
// userinfo. They run after the token rules, so a value the token rules
// already masked stays masked.
var contextRules = []patternRule{
	{
		re:   regexp.MustCompile(`(\bsecurity\s+[a-z-]*password\b[^|;&\n]*?\s-w)\s+('[^']*'|"[^"]*"|[^\s-]\S*)`),
		repl: "${1} [REDACTED]",
		keep: isMask,
	},
	{
		re:   regexp.MustCompile(`(?i)(\s--?password(?:-phrase)?)\s+('[^']*'|"[^"]*"|[^\s-]\S*)`),
		repl: "${1} [REDACTED]",
		keep: isMask,
	},
	{
		re:   regexp.MustCompile(`(?i)\b((?:[a-z0-9]+_)*(?:password|passwd|secret|token|api[_-]?key|aws_secret_access_key)\w*\s*[:=]\s*)('[^']*'|"[^"]*"|\S+)`),
		repl: "${1}[REDACTED]",
		keep: isMask,
	},
	{
		re:   regexp.MustCompile(`://[^/\s:@]+:([^@\s]+)@`),
		repl: "://[REDACTED]@",
		keep: func(v string) bool { return isMask(v) || portPathRE.MatchString(v) },
	},
}

// tokenRules match credentials by their own shape.
var tokenRules = []patternRule{
	{
		name:   "bearer-token",
		re:     regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`),
		repl:   "Bearer [REDACTED]",
		detect: regexp.MustCompile(`Bearer\s+[A-Za-z0-9\-._~+/]+=*`),
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

// apply masks every match of r in s whose value r.keep does not exempt.
func (r patternRule) apply(s string) string {
	if r.keep == nil {
		return r.re.ReplaceAllString(s, r.repl)
	}
	var b strings.Builder
	last := 0
	for _, m := range r.re.FindAllStringSubmatchIndex(s, -1) {
		if r.keep(s[m[len(m)-2]:m[len(m)-1]]) {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.Write(r.re.ExpandString(nil, r.repl, s, m))
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func Scrub(s string) string {
	res := PrivateKeys(s)
	for _, r := range tokenRules {
		res = r.apply(res)
	}
	for _, r := range contextRules {
		res = r.apply(res)
	}
	return res
}

// Detect names the first credential shape in s. Context rules are not
// consulted: a credential-named key alone is not evidence of a secret.
func Detect(s string) (string, bool) {
	for _, r := range tokenRules {
		re := r.re
		if r.detect != nil {
			re = r.detect
		}
		if re.MatchString(s) {
			return r.name, true
		}
	}
	return "", false
}
