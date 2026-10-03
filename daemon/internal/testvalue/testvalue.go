// Package testvalue tells test, dummy and sentinel credentials from live
// ones by value-free signals: markers in the value, its shape, published
// sample values, and the text around it. Reasons come from a fixed
// vocabulary and never carry the value; a reason names at most a vocabulary
// word or a file name. The local advisor and the local agent weigh them.
//
// Value reasons (Strong) describe the value itself. Context reasons describe
// only its surroundings: a real key pasted into a test is still a leak.
package testvalue

import (
	"encoding/base64"
	"path"
	"regexp"
	"strings"
)

// Reason phrases. The ones built with a %s detail are prefixes.
const (
	PublishedSample = "a published sample value"
	PlaceholderWord = "a placeholder word in the value"
	TestModePrefix  = "a test-mode key prefix"
	LowEntropy      = "a low-entropy value (repeated or sequential characters)"
	DecodesDummy    = "decodes to a placeholder credential"
	SampleJWT       = "a JWT with sample claims"
	TestFile        = "a test or example file named in the same record"
	TestCode        = "test code around it"
	DummyWording    = "dummy, sample or redaction wording around it"
)

// contextWindow is how many bytes on each side of the value count as its
// surroundings.
const contextWindow = 240

// publishedSamples are credentials vendors publish in their documentation.
// Written in fragments so secret scanners reading this source stay quiet.
var publishedSamples = map[string]bool{
	"AKIA" + "IOSFODNN7EXAMPLE":                     true, // AWS access key id
	"wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY": true, // AWS secret access key
	"AKIA" + "I44QH8DHBEXAMPLE":                     true,
	"je7MtGbClwBF/2Zp9Utk/" + "h3yCo8nvbEXAMPLEKEY": true,
	JWTIOSample: true,
}

// JWTIOSample is jwt.io's default token.
const JWTIOSample = "eyJhbGciOiJIUzI1NiIsInR5cCI6" + "IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6" + "IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_" + "adQssw5c"

// placeholderWords mark a value written as a stand-in.
var placeholderWords = []string{
	"example", "sample", "dummy", "fake", "placeholder", "changeme", "change_me",
	"replace_me", "replaceme", "redacted", "notreal", "not_real", "not-a-real",
	"xxxx", "your_", "your-", "foobar", "mock", "fixture", "testing", "test_", "_test", "-test",
}

// testModePrefixes are vendor keys that only work against a sandbox.
var testModePrefixes = []string{"sk_test_", "pk_test_", "rk_test_", "whsec_test_"}

// dummyCredentials are decoded values that are placeholders, Kubernetes and
// Docker documentation examples included.
var dummyCredentials = map[string]bool{
	"admin": true, "password": true, "passw0rd": true, "changeme": true, "secret": true,
	"test": true, "testing": true, "example": true, "root": true, "postgres": true,
	"guest": true, "user": true, "username": true, "letmein": true, "123456": true,
	"qwerty": true, "1f2d1e2e67df": true, "dummy": true, "fake": true, "pass": true,
	"testuser": true, "testpassword": true,
}

var (
	testCodeRE     = regexp.MustCompile(`(?:\b(?:expect|assert\w*|it|describe|test|t\.Run|require\.\w+|XCTAssert\w*)\s*\(|\bdef test_|\bfunc Test|@Test\b|\b(?:vitest|jest|pytest|unittest|RSpec)\b)`)
	dummyWordingRE = regexp.MustCompile(`(?i)\b(?:fake|dummy|example|sample|placeholder|sentinel|mock|stub|fixture|not a real|redact\w*|scrub\w*)\b`)
	filePathRE     = regexp.MustCompile(`[\w.@/-]+\.(?:tsx?|jsx?|mjs|cjs|py|go|rb|java|kt|swift|rs|cs|php|ya?ml|json|toml|ini|cfg|conf|sh|txt|md)\b|[\w.@/-]*\.env\.(?:example|sample|test|template)\b`)
	testDirs       = map[string]bool{
		"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "testdata": true,
		"fixture": true, "fixtures": true, "mocks": true, "__mocks__": true, "example": true, "examples": true,
	}
	testFileRE = regexp.MustCompile(`(?i)(?:[._-](?:test|spec)\.|^test_|\.(?:example|sample|template)$|\.env\.(?:example|sample|test|template)$)`)
	jwtRE      = regexp.MustCompile(`^eyJ[\w-]*\.(eyJ[\w-]*)\.[\w-]*$`)
	sampleJWT  = regexp.MustCompile(`(?i)john doe|jane doe|example\.(?:com|org)|"sub":"1234567890"|"test`)
)

// Signals returns the reasons the value at text[start:end] looks like a test,
// dummy or sentinel value; nil when nothing marks it or the span is invalid.
func Signals(text string, start, end int) []string {
	if start < 0 || end > len(text) || start >= end {
		return nil
	}
	v := text[start:end]
	var out []string
	add := func(r string) {
		for _, have := range out {
			if have == r {
				return
			}
		}
		out = append(out, r)
	}

	lower := strings.ToLower(v)
	if publishedSamples[v] {
		add(PublishedSample)
	}
	for _, p := range testModePrefixes {
		if strings.HasPrefix(lower, p) {
			add(TestModePrefix)
		}
	}
	for _, w := range placeholderWords {
		if strings.Contains(lower, w) && !(strings.Contains(w, "test") && hasTestModePrefix(lower)) {
			add(PlaceholderWord + " (" + strings.Trim(w, "_-") + ")")
			break
		}
	}
	if lowEntropy(v) {
		add(LowEntropy)
	}
	if decodesToDummy(v) {
		add(DecodesDummy)
	}
	if m := jwtRE.FindStringSubmatch(v); m != nil {
		if claims, err := base64.RawURLEncoding.DecodeString(m[1]); err == nil && sampleJWT.Match(claims) {
			add(SampleJWT)
		}
	}

	if f := testFileIn(text); f != "" {
		add(TestFile + " (" + f + ")")
	}
	around := text[max(0, start-contextWindow):start] + " " + text[end:min(len(text), end+contextWindow)]
	if testCodeRE.MatchString(around) {
		add(TestCode)
	}
	if dummyWordingRE.MatchString(around) {
		add(DummyWording)
	}
	return out
}

// Strong reports whether any reason describes the value itself rather than
// its surroundings.
func Strong(reasons []string) bool {
	for _, r := range reasons {
		if !strings.HasPrefix(r, TestFile) && r != TestCode && r != DummyWording {
			return true
		}
	}
	return false
}

func hasTestModePrefix(lower string) bool {
	for _, p := range testModePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// lowEntropy: few distinct characters, a long run of one character, or a
// long ascending run (0123456789, abcdefgh).
func lowEntropy(v string) bool {
	distinct := map[rune]bool{}
	run, longest := 0, 0
	seq, longestSeq := 1, 1
	var prev rune
	for i, r := range v {
		distinct[r] = true
		if i > 0 && r == prev {
			run++
		} else {
			run = 1
		}
		if i > 0 && r == prev+1 {
			seq++
		} else {
			seq = 1
		}
		longest = max(longest, run)
		longestSeq = max(longestSeq, seq)
		prev = r
	}
	return len(distinct) <= 6 || longest >= 6 || longestSeq >= 8
}

// decodesToDummy: the value, or its part after the last separator, is
// base64 for a placeholder credential or a user:password pair of them.
func decodesToDummy(v string) bool {
	cands := []string{v}
	if i := strings.LastIndexAny(v, "_-:= "); i >= 0 && i+1 < len(v) {
		cands = append(cands, v[i+1:])
	}
	for _, c := range cands {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			b, err := enc.DecodeString(c)
			if err != nil || len(b) == 0 {
				continue
			}
			s := strings.ToLower(strings.TrimSpace(string(b)))
			if dummyCredentials[s] {
				return true
			}
			if user, pass, ok := strings.Cut(s, ":"); ok && dummyCredentials[user] && dummyCredentials[pass] {
				return true
			}
		}
	}
	return false
}

// testFileIn returns the base name of the first test, fixture or example
// file the text names; "" when none.
func testFileIn(text string) string {
	for _, p := range filePathRE.FindAllString(text, -1) {
		p = strings.TrimRight(strings.TrimPrefix(p, "./"), ".")
		base := path.Base(p)
		if testFileRE.MatchString(base) {
			return base
		}
		for _, seg := range strings.Split(path.Dir(p), "/") {
			if testDirs[strings.ToLower(seg)] {
				return base
			}
		}
	}
	return ""
}
