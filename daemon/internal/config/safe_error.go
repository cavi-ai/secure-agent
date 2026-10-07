package config

import (
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
)

// backtickValueRE is a value a yaml.v3 error quotes ("cannot unmarshal !!str
// `x` into int"). The value may itself hold backticks, so the span runs to
// the last one on its line.
var backtickValueRE = regexp.MustCompile("`.*`")

// goQuotedValueRE is a value a validation error quotes with %q.
var goQuotedValueRE = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// SafeError renders an overlay or validation error for Doctor and logs: the
// values it quotes become "a value", credential shapes are scrubbed, and its
// lines are joined into one. The overlay is user-owned and can hold secrets.
func SafeError(err error) string {
	if err == nil {
		return ""
	}
	var parts []string
	for _, line := range strings.Split(err.Error(), "\n") {
		line = backtickValueRE.ReplaceAllString(line, "a value")
		line = goQuotedValueRE.ReplaceAllString(line, "a value")
		if line = strings.Join(strings.Fields(line), " "); line != "" {
			parts = append(parts, line)
		}
	}
	return redact.Scrub(strings.Join(parts, " "))
}
