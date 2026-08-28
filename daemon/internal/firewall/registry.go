package firewall

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// Fingerprint returns hex HMAC-SHA256(salt, secret). The salt is per-install so
// fingerprints are not portable and cannot act as a shared secret oracle.
func Fingerprint(salt []byte, secret string) string {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

type Registry struct {
	salt   []byte
	byHMAC map[string]config.Fingerprint
	byLen  map[int]struct{} // candidate token lengths to consider
}

func NewRegistry(salt []byte, fps []config.Fingerprint) *Registry {
	r := &Registry{salt: salt, byHMAC: map[string]config.Fingerprint{}, byLen: map[int]struct{}{}}
	for _, f := range fps {
		r.byHMAC[f.HMAC] = f
		if f.Len > 0 {
			r.byLen[f.Len] = struct{}{}
		}
	}
	return r
}

// Match tokenizes each normalized view of data and reports any token whose
// HMAC matches a registered fingerprint. Only tokens whose length matches a
// registered length are hashed, keeping the scan cheap.
func (r *Registry) Match(data []byte) []Hit {
	if len(r.byHMAC) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var hits []Hit
	for _, view := range Normalize(data) {
		for _, tok := range strings.FieldsFunc(view, isTokenBreak) {
			if _, ok := r.byLen[len(tok)]; !ok {
				continue
			}
			h := Fingerprint(r.salt, tok)
			fp, ok := r.byHMAC[h]
			if !ok {
				continue
			}
			if _, dup := seen[fp.ID]; dup {
				continue
			}
			seen[fp.ID] = struct{}{}
			st := fp.Type
			if st == "" {
				st = TypeEnvValue
			}
			hits = append(hits, Hit{RuleID: fp.ID, SecretType: st, Layer: LayerFingerprint, Confidence: 1.0})
		}
	}
	return hits
}

// Ingest reads KEY=VALUE style files and returns fingerprints of the values.
// Raw values are never returned or stored.
func Ingest(sources []string, salt []byte) ([]config.Fingerprint, error) {
	var out []config.Fingerprint
	n := 0
	for _, src := range sources {
		f, err := os.Open(src)
		if err != nil {
			continue // a missing source is not an error
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq <= 0 {
				continue
			}
			key := strings.TrimSpace(line[:eq])
			val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
			if len(val) < 8 { // ignore trivially short / empty values
				continue
			}
			n++
			out = append(out, config.Fingerprint{
				ID:    "fp-" + strconv.Itoa(n),
				Type:  TypeEnvValue,
				Len:   len(val),
				Label: key + " (" + src + ")",
				HMAC:  Fingerprint(salt, val),
			})
			val = "" // drop plaintext immediately
			_ = val
		}
		f.Close()
	}
	return out, nil
}
