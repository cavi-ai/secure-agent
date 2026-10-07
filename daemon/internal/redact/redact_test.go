package redact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sharedCases is testdata/cases.json, which the Python hooks' redaction must
// satisfy too. Secret values are assembled at run time so no
// credential-shaped literal is committed; PEM names a private-key block
// wrapped around the body. Exact cases pin the output both must produce.
type sharedCases struct {
	Secrets []struct {
		Name   string `json:"name"`
		PEM    string `json:"pem"`
		Before string `json:"before"`
		Prefix string `json:"prefix"`
		Fill   string `json:"fill"`
		N      int    `json:"n"`
		After  string `json:"after"`
	} `json:"secrets"`
	Exact []struct {
		Name string `json:"name"`
		In   string `json:"in"`
		Want string `json:"want"`
	} `json:"exact"`
}

func loadSharedCases(t *testing.T) sharedCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases sharedCases
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases.Secrets) == 0 || len(cases.Exact) == 0 {
		t.Fatal("no shared cases")
	}
	return cases
}

func TestScrubSharedSecretCases(t *testing.T) {
	for _, c := range loadSharedCases(t).Secrets {
		body := strings.Repeat(c.Fill, c.N)
		before, after := c.Before, c.After
		if c.PEM != "" {
			before += "-----BEGIN " + c.PEM + " PRIVATE KEY-----\n"
			after = "\n-----END " + c.PEM + " PRIVATE KEY-----" + after
		}
		got := Scrub(before + c.Prefix + body + after)
		if strings.Contains(got, body) || !strings.Contains(got, "[REDACTED") {
			t.Errorf("%s: Scrub = %q", c.Name, got)
		}
	}
}

func TestScrubSharedExactCases(t *testing.T) {
	for _, c := range loadSharedCases(t).Exact {
		if got := Scrub(c.In); got != c.Want {
			t.Errorf("%s: Scrub(%q) = %q, want %q", c.Name, c.In, got, c.Want)
		}
	}
}

func TestDetectNamesTokenShapes(t *testing.T) {
	for in, want := range map[string]string{
		"sk-ant-api03-" + strings.Repeat("a", 30): "provider-key",
		"ghp_" + strings.Repeat("d", 36):          "github-token",
		"glpat-" + strings.Repeat("e", 20):        "gitlab-token",
		"xoxb-" + strings.Repeat("1", 24):         "slack-token",
	} {
		if rule, found := Detect(in); !found || rule != want {
			t.Errorf("Detect(%.8q) = %q,%v; want %q", in, rule, found, want)
		}
	}
	for _, in := range []string{"export API_KEY=placeholder", "the bearer of this note"} {
		if rule, found := Detect(in); found {
			t.Errorf("Detect(%q) = %q; want no hit", in, rule)
		}
	}
}

func TestScrub(t *testing.T) {
	in := "auth: Bearer abc123DEF.-_ and jwt eyJhbG.eyJzdWI.sig"
	out := Scrub(in)
	if strings.Contains(out, "abc123DEF") {
		t.Fatal("bearer token not redacted")
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatal("expected redaction marker")
	}
}

func TestDetectNeverLeaksValue(t *testing.T) {
	rule, found := Detect("Bearer sk-secretvalue")
	if !found || rule != "bearer-token" {
		t.Fatalf("Detect = %q,%v; want bearer-token,true", rule, found)
	}
}

func TestScrubPrivateKeyEnvelopes(t *testing.T) {
	for _, kind := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		for _, newline := range []string{"\n", `\n`} {
			text := "before " + "-----BEGIN " + kind + "-----" + newline + "synthetic-key-body" + newline + "-----END " + kind + "----- after"
			got := Scrub(text)
			if strings.Contains(got, "synthetic-key-body") || !strings.Contains(got, "before ") || !strings.Contains(got, " after") {
				t.Errorf("scrub failed for %s envelope", kind)
			}
		}
	}
	public := "-----BEGIN PUBLIC KEY-----\nsynthetic-public-body\n-----END PUBLIC KEY-----"
	if got := Scrub(public); got != public {
		t.Fatal("public key was masked")
	}
}
