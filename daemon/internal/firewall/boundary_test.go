package firewall

import (
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func boundaryDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := NewDetector([]config.PatternConfig{
		{ID: "openai-key", Type: TypeVendorKey, Re: `sk-[A-Za-z0-9]{32,}`},
		{ID: "twilio-sid", Type: TypeCloudKey, Re: `AC[0-9a-fA-F]{32}`},
	}, config.EntropyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func hitIDs(hits []Hit) string {
	var ids []string
	for _, h := range hits {
		ids = append(ids, h.RuleID)
	}
	return strings.Join(ids, ",")
}

// A pattern counts only where it starts a token: inside a base64 or
// base64url blob (an encrypted reasoning item, an image) the same characters
// are noise. A JSON escape (\n, \t, \r) ends the previous token.
func TestPatternsMatchOnlyAtTokenStart(t *testing.T) {
	d := boundaryDetector(t)
	key := "sk-" + strings.Repeat("A1b2", 9)
	sid := "AC" + strings.Repeat("0f", 16)
	blob := "gAAAAABo" + strings.Repeat("Zx9_", 40)
	for _, c := range []struct {
		name, text, want string
	}{
		{"inside base64url, alnum before", `{"encrypted_content":"` + blob + "x" + key + blob + `"}`, ""},
		{"inside base64url, dash before", `{"encrypted_content":"` + blob + "-" + key + `"}`, ""},
		{"inside base64, slash before", `{"data":"` + blob + "/" + key + `"}`, ""},
		{"assignment", "OPENAI_API_KEY=" + key, "openai-key"},
		{"JSON string start", `{"output":"` + key + `"}`, "openai-key"},
		{"after an escaped newline", `{"output":"line one\n` + key + `"}`, "openai-key"},
		{"after an escaped tab", `{"output":"k\t` + key + `"}`, "openai-key"},
		{"text start", key, "openai-key"},
		{"after a space", "use " + key, "openai-key"},
		{"mid-token first, then a real one", blob + "x" + key + " and " + key, "openai-key"},
		{"sid inside a hex blob", "deadbeef" + sid, ""},
		{"sid standalone", "sid " + sid, "twilio-sid"},
	} {
		if got := hitIDs(d.ScanPatterns(c.text)); got != c.want {
			t.Errorf("%s: hits %q, want %q", c.name, got, c.want)
		}
	}
}

// The engine's text scan (the transcript tailer's scanner) inherits the rule.
func TestScanTextIgnoresPatternsInsideEncodedBlobs(t *testing.T) {
	e, err := NewEngine(config.FirewallConfig{Mode: "monitor", Patterns: []config.PatternConfig{
		{ID: "openai-key", Type: TypeVendorKey, Re: `sk-[A-Za-z0-9]{32,}`, Mode: "monitor"},
	}}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	line := `{"type":"response_item","payload":{"type":"reasoning","encrypted_content":"gAAAAABo` +
		strings.Repeat("Qz9_", 50) + "k" + "sk-" + strings.Repeat("Ab12", 9) + strings.Repeat("-_Zz", 30) + `"}}`
	if hits := e.ScanText(line); len(hits) != 0 {
		t.Fatalf("encrypted reasoning blob: hits %q, want none", hitIDs(hits))
	}
}
