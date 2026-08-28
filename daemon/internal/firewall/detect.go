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

func (d *Detector) Scan(text string) []Hit {
	var hits []Hit
	for _, p := range d.patterns {
		if p.re.MatchString(text) {
			hits = append(hits, Hit{RuleID: p.id, SecretType: p.secretType, Layer: LayerPattern, Confidence: 0.9})
		}
	}
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
