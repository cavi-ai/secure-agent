package firewall

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// A registered secret written out byte by byte in another encoding is still a
// fingerprint hit: a decimal or 0x byte list (the form Ghostcommit commits),
// hex, \x escapes, and URL-safe or unpadded base64.
func TestMatchFindsEncodedRegisteredSecret(t *testing.T) {
	salt := []byte("test-salt")
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	reg := NewRegistry(salt, []config.Fingerprint{{ID: "aws-secret", HMAC: Fingerprint(salt, secret), Len: len(secret), Type: "aws-secret"}})
	// The trailing 0xfb 0xff bytes put '+' and '/' in standard base64 ('-' and
	// '_' URL-safe), and the length keeps unpadded base64 off a 4-byte boundary.
	env := []byte("AWS_REGION=us-east-1\nAWS_SECRET_ACCESS_KEY=" + secret + "\n#\xfb\xff")
	for len(env)%3 == 0 {
		env = append(env, ' ')
	}
	if u := base64.URLEncoding.EncodeToString(env); !strings.ContainsAny(u, "-_") {
		t.Fatalf("fixture: URL-safe base64 has no URL-safe characters: %s", u)
	}

	var dec, oxs, esc []string
	for _, b := range env {
		dec = append(dec, strconv.Itoa(int(b)))
		oxs = append(oxs, fmt.Sprintf("0x%02x", b))
		esc = append(esc, fmt.Sprintf(`\x%02x`, b))
	}
	for name, body := range map[string]string{
		"decimal list":                "const buildSpec = [" + strings.Join(dec, ", ") + "];",
		"decimal compact":             strings.Join(dec, ","),
		"0x list":                     "uint8_t spec[] = {" + strings.Join(oxs, ", ") + "};",
		"hex":                         "checksum: " + hex.EncodeToString(env),
		"hex after a stray hex digit": "checksum: a" + hex.EncodeToString(env),
		"hex escapes":                 `payload = b"` + strings.Join(esc, "") + `"`,
		"url-safe base64":             "d=" + base64.URLEncoding.EncodeToString(env),
		"unpadded base64":             "d=" + base64.RawStdEncoding.EncodeToString(env),
	} {
		hits := reg.Match([]byte(body))
		if len(hits) != 1 || hits[0].RuleID != "aws-secret" || hits[0].Layer != LayerFingerprint {
			t.Errorf("%s: hits = %+v", name, hits)
		}
	}

	// Numbers that are not bytes, and hex that decodes to no registered secret,
	// raise nothing.
	for _, body := range []string{
		"[1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000]",
		"sha256: " + hex.EncodeToString([]byte("an ordinary build artifact digest!")),
	} {
		if hits := reg.Match([]byte(body)); len(hits) != 0 {
			t.Errorf("%q: hits = %+v", body, hits)
		}
	}
}

// A canary file in the form `secure-agent canary plant` writes registers its
// values, and the file leaving as a byte list in a commit-shaped body is a hit.
func TestIngestedCanaryFileMatchesWhenLeakedAsBytes(t *testing.T) {
	salt := []byte("test-salt")
	// Built from fragments so the repository secret scan does not flag the fixture.
	file := "AWS_ACCESS_KEY_ID=" + "AKIA" + "Q7LZXN2M4KD5RW3B\n" +
		"AWS_SECRET_ACCESS_KEY=" + "Zp4+qL8vT2/xN6kR0mW3" + "sJ9yB1cF5hD7gA2eQ8uY\n" +
		"GITHUB_TOKEN=" + "ghp" + "_R8x2kL9mQ4vT7nW1pZ5sY3bC6dF0hJ2gA8eK\n"
	path := filepath.Join(t.TempDir(), "canary.env")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	fps, err := Ingest([]string{path}, salt)
	if err != nil || len(fps) < 3 {
		t.Fatalf("ingest = %d fingerprints, %v", len(fps), err)
	}
	reg := NewRegistry(salt, fps)
	var dec []string
	for _, b := range []byte(file) {
		dec = append(dec, strconv.Itoa(int(b)))
	}
	body := "diff --git a/src/spec.js b/src/spec.js\n+export const spec = [" + strings.Join(dec, ", ") + "];\n"
	if hits := reg.Match([]byte(body)); len(hits) < 3 {
		t.Fatalf("hits = %+v, want each canary value", hits)
	}
}
