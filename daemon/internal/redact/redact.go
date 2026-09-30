package redact

import (
	"regexp"
)

type patternRule struct {
	name string
	re   *regexp.Regexp
}

// PrivateKeys removes the entire PEM envelope, rather than only the marker
// used to detect it. An unterminated envelope withholds the remaining text.
var privateKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)`)

func PrivateKeys(s string) string {
	return privateKeyRE.ReplaceAllLiteralString(s, "[REDACTED:private-key]")
}

var rules = []patternRule{
	{
		name: "bearer-token",
		re:   regexp.MustCompile(`Bearer\s+[A-Za-z0-9\-._~+/]+=*`),
	},
	{
		name: "jwt-token",
		re:   regexp.MustCompile(`\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b`),
	},
	{
		name: "aws-access-key",
		re:   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
}

func Scrub(s string) string {
	res := PrivateKeys(s)
	for _, r := range rules {
		res = r.re.ReplaceAllString(res, "[REDACTED]")
	}
	return res
}

func Detect(s string) (string, bool) {
	for _, r := range rules {
		if r.re.MatchString(s) {
			return r.name, true
		}
	}
	return "", false
}
