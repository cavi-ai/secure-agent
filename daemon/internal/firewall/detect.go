package firewall

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type compiledPattern struct {
	id, secretType string
	re             *regexp.Regexp
}

type Detector struct {
	patterns []compiledPattern
	entropy  config.EntropyConfig
}

func NewDetector(pats []config.PatternConfig, ent config.EntropyConfig) (*Detector, error) {
	d := &Detector{entropy: ent}
	for _, p := range pats {
		re, err := regexp.Compile(p.Re)
		if err != nil {
			return nil, fmt.Errorf("firewall pattern %q: %w", p.ID, err)
		}
		st := p.Type
		if st == "" {
			st = TypeUnknown
		}
		d.patterns = append(d.patterns, compiledPattern{id: p.ID, secretType: st, re: re})
	}
	return d, nil
}

// Scan returns the typed-pattern hits plus, when enabled, one entropy hit.
func (d *Detector) Scan(text string) []Hit {
	hits := d.ScanPatterns(text)
	if d.entropy.Enabled {
		for _, tok := range strings.FieldsFunc(text, isTokenBreak) {
			if len(tok) >= d.entropy.MinLen && shannonBits(tok) >= d.entropy.MinBits {
				hits = append(hits, Hit{RuleID: "entropy", SecretType: TypeUnknown, Layer: LayerEntropy, Confidence: 0.4})
				break // one entropy hit per payload is enough signal
			}
		}
	}
	return hits
}

// MaskPatterns replaces every typed-pattern match in text with
// [REDACTED:<pattern id>].
func (d *Detector) MaskPatterns(text string) string {
	for _, p := range d.patterns {
		text = p.re.ReplaceAllLiteralString(text, "[REDACTED:"+p.id+"]")
	}
	return text
}

// ScanPatterns returns the typed-pattern hits only; the entropy layer is
// never run. A match counts only where it starts a token (startsToken).
func (d *Detector) ScanPatterns(text string) []Hit {
	var hits []Hit
	for _, p := range d.patterns {
		if matchesAtTokenStart(p.re, text) {
			hits = append(hits, Hit{RuleID: p.id, SecretType: p.secretType, Layer: LayerPattern, Confidence: 0.9})
		}
	}
	return hits
}

// matchesAtTokenStart reports whether re matches text at a token start.
func matchesAtTokenStart(re *regexp.Regexp, text string) bool {
	for _, m := range re.FindAllStringIndex(text, -1) {
		if startsToken(text, m[0]) {
			return true
		}
	}
	return false
}

// startsToken reports whether position i begins a token: the byte before it
// is not a base64 or base64url character, or it ends a JSON escape (\n, \t,
// \r). Vendor-key shapes occur by chance inside encoded blobs (encrypted
// reasoning items, images); there they follow such a character.
func startsToken(text string, i int) bool {
	if i == 0 {
		return true
	}
	c := text[i-1]
	isB64 := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-'
	if !isB64 {
		return true
	}
	return i >= 2 && text[i-2] == '\\' && (c == 'n' || c == 't' || c == 'r')
}

func isTokenBreak(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '"', '\'', '=', ':', ',', ';', '{', '}', '[', ']', '(', ')', '<', '>', '&':
		return true
	}
	return false
}

func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var bits float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		bits -= p * math.Log2(p)
	}
	return bits
}
