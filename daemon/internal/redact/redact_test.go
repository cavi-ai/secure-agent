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
