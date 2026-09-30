package redact

import (
	"strings"
	"testing"
)

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
