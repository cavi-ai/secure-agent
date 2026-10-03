package testvalue

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// span locates v in text.
func span(t *testing.T, text, v string) (int, int) {
	t.Helper()
	i := strings.Index(text, v)
	if i < 0 {
		t.Fatalf("%q not in text", v)
	}
	return i, i + len(v)
}

// Random-looking key bodies built from fragments so no literal reads as a
// credential.
var (
	liveKey = "sk-ant-" + "api03-" + "Qz7Lk2Vb9Rt4Wm1Xc8Np5Hj3Gd6Fs0Ae" + "Yu2Io9Pl4Kj7Mn"
	ghToken = "ghp_" + "Lm3Nq8Rt2Vw6Yz1Bc5Df9Gh4Jk7Mp0Qs3Tu"
)

func TestSignals(t *testing.T) {
	k8s := base64.StdEncoding.EncodeToString([]byte("admin"))
	dockerAuth := base64.StdEncoding.EncodeToString([]byte("username:password"))
	// Samples in fragments so secret scanners reading this file stay quiet.
	awsID := "AKIA" + "IOSFODNN7EXAMPLE"
	openaiPlaceholder := "sk-" + "proj-" + "your_key_here_replace_me_1234"
	stripeTest := "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
	ghRun := "ghp_" + strings.Repeat("x", 36)
	alphabetKey := "sk-ant-" + "api03-" + "abcdefghijklmnopqrstuvwxyz" + "0123"
	for _, tc := range []struct {
		name, text, value string
		want              []string // each reason must appear (prefix match)
		strong            bool
	}{
		{"a live key in prose has no signal", "export ANTHROPIC_API_KEY=" + liveKey + " # prod", liveKey, nil, false},
		{"a live token in a command has no signal", `git remote set-url origin https://` + ghToken + `@github.com/acme/app`, ghToken, nil, false},
		{"the vendor's published sample", `aws_access_key_id = ` + awsID, awsID, []string{PublishedSample, PlaceholderWord}, true},
		{"a placeholder word", `OPENAI_API_KEY=` + openaiPlaceholder, openaiPlaceholder, []string{PlaceholderWord}, true},
		{"a test-mode prefix", `stripe.api_key = "` + stripeTest + `"`, stripeTest, []string{TestModePrefix}, true},
		{"repeated characters", `token: ` + ghRun, ghRun, []string{LowEntropy, PlaceholderWord}, true},
		{"a sequential run", `key=` + alphabetKey, alphabetKey, []string{LowEntropy}, true},
		{"a Kubernetes Secret documentation value", "kind: Secret\ndata:\n  username: " + k8s + "\n", k8s, []string{DecodesDummy}, true},
		{"a Docker config auth for username:password", `{"auths":{"registry.example.com":{"auth":"` + dockerAuth + `"}}}`, dockerAuth, []string{DecodesDummy}, true},
		{"jwt.io's sample token", "Authorization: Bearer " + JWTIOSample, JWTIOSample, []string{PublishedSample, SampleJWT}, true},
		{
			"a random-looking key in a test file being written: context only",
			`cat > test/memory/record.test.ts <<'EOF'\n  it("scrubs secrets from the fact", () => {\n    const line = format({ fact: "Key is ` + liveKey + ` ok" });\n    expect(line).not.toContain("sk-ant-");`,
			liveKey, []string{TestFile + " (record.test.ts)", TestCode, DummyWording}, false,
		},
		{"an env template", `cp .env.example .env # STRIPE_KEY=` + liveKey, liveKey, []string{TestFile + " (.env.example)"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := span(t, tc.text, tc.value)
			got := Signals(tc.text, s, e)
			if tc.want == nil && got != nil {
				t.Fatalf("signals = %q, want none", got)
			}
			for _, w := range tc.want {
				if !slices.ContainsFunc(got, func(r string) bool { return strings.HasPrefix(r, w) }) {
					t.Fatalf("signals = %q, want %q", got, w)
				}
			}
			if Strong(got) != tc.strong {
				t.Fatalf("Strong(%q) = %v, want %v", got, Strong(got), tc.strong)
			}
			for _, r := range got {
				if strings.Contains(r, tc.value) {
					t.Fatalf("reason %q carries the value", r)
				}
			}
		})
	}
}

func TestSignalsRejectsABadSpan(t *testing.T) {
	for _, sp := range [][2]int{{-1, 3}, {3, 3}, {2, 99}} {
		if got := Signals("abcdef", sp[0], sp[1]); got != nil {
			t.Fatalf("Signals(%v) = %q, want nil", sp, got)
		}
	}
}
