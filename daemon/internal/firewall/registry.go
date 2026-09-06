package firewall

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// maxIngestBytes caps the size of a single source file we will scan. Sources
// are user-supplied paths; a runaway file (a huge log pointed at by mistake)
// must not stall an ingest. Real secret files (.env, credentials) are tiny.
const maxIngestBytes = 10 << 20 // 10 MiB

// maxIngestLineBytes caps one source line. The default bufio.Scanner limit is
// 64 KiB; a longer line silently truncates the scan of that file (sc.Err()
// reports ErrTooLong), which is how a source with one long line used to lose
// every secret after it without any signal.
const maxIngestLineBytes = 1 << 20 // 1 MiB

// Ingest reads KEY=VALUE style files and returns fingerprints of the values.
// Raw values are never returned or stored.
//
// Failure semantics matter: the caller persists the returned set wholesale, so
// a run that read NOTHING (every source missing/unreadable/oversized) returns
// an error instead of an empty set — persisting an empty set would silently
// purge every previously registered fingerprint and turn the highest-precision
// detection layer off while the status page says it's up.
func Ingest(sources []string, salt []byte) ([]config.Fingerprint, error) {
	var out []config.Fingerprint
	var failed []string
	n := 0
	for _, src := range sources {
		if fi, err := os.Stat(src); err != nil || fi.IsDir() || fi.Size() > maxIngestBytes {
			failed = append(failed, src)
			continue
		}
		f, err := os.Open(src)
		if err != nil {
			failed = append(failed, src)
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxIngestLineBytes)
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
			// Note: val is a string — zeroing it is a no-op. The plaintext only
			// lives in `line`/`val` for the duration of this iteration; nothing
			// persists it (the fingerprint carries HMAC, type, length, label).
		}
		if err := sc.Err(); err != nil {
			failed = append(failed, src+" (scan error: "+err.Error()+")")
		}
		f.Close()
	}
	if len(out) == 0 && len(failed) > 0 {
		return nil, fmt.Errorf("ingest produced zero fingerprints and every source failed (%s); refusing to return an empty set that would purge the registered fingerprints", strings.Join(failed, ", "))
	}
	return out, nil
}
