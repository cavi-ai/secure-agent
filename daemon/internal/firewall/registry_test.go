package firewall

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestRegistryMatchesRegisteredSecretAcrossEncodings(t *testing.T) {
	salt := []byte("test-salt")
	secret := "s3cr3t-value-abcdefghijklmnop"
	fp := config.Fingerprint{ID: "fp1", Type: TypeEnvValue, Len: len(secret), HMAC: Fingerprint(salt, secret)}
	r := NewRegistry(salt, []config.Fingerprint{fp})

	if got := r.Match([]byte("Authorization: " + secret)); len(got) == 0 || got[0].RuleID != "fp1" {
		t.Fatalf("raw match failed: %+v", got)
	}
	// base64-wrapped occurrence must still match via Normalize
	enc := []byte("blob=" + base64Std(secret))
	if got := r.Match(enc); len(got) == 0 {
		t.Fatal("base64-wrapped secret should match")
	}
}

func TestRegistryMaskTokensUsesOriginalTokenSpans(t *testing.T) {
	salt := []byte("test-salt")
	const short = "fixture-alpha"
	const long = short + "-plus"
	const unicode = "clé-fixture-123"
	r := NewRegistry(salt, []config.Fingerprint{
		{ID: "short", Len: len(short), HMAC: Fingerprint(salt, short)},
		{ID: "long", Len: len(long), HMAC: Fingerprint(salt, long)},
		{ID: "unicode", Len: len(unicode), HMAC: Fingerprint(salt, unicode)},
	})
	for _, tc := range []struct{ name, input, want string }{
		{"short-before-long", short + " " + long, "[REDACTED:short] [REDACTED:long]"},
		{"long-before-short", long + " " + short, "[REDACTED:long] [REDACTED:short]"},
		{"substring-after-hit", short + " prefix-" + short + "-suffix", "[REDACTED:short] prefix-" + short + "-suffix"},
		{"substring-before-hit", "prefix-" + short + "-suffix " + short, "prefix-" + short + "-suffix [REDACTED:short]"},
		{"repeated", short + "," + short + ";" + long, "[REDACTED:short],[REDACTED:short];[REDACTED:long]"},
		{"unicode-and-delimiters", "début={\"clé\":\"" + unicode + "\"}\r\n", "début={\"clé\":\"[REDACTED:unicode]\"}\r\n"},
		{"no-hit", "prefix-" + short + "-suffix", "prefix-" + short + "-suffix"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.MaskTokens(tc.input); got != tc.want {
				t.Fatalf("masked text = %q, want %q", got, tc.want)
			}
		})
	}
}

type ingestCountingReader struct {
	io.Reader
	bytesRead int
}

func (r *ingestCountingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytesRead += n
	return n, err
}

func TestIngestSourceReadLimit(t *testing.T) {
	const prefix = "FIRST=first-fixture-value\n"
	for _, size := range []int{maxIngestBytes - 1, maxIngestBytes, maxIngestBytes + 1, 2 * maxIngestBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			// Short comment lines exercise the total limit independently of the
			// per-line scanner limit. A valid prefix must never escape on overflow.
			padding := size - len(prefix)
			input := io.MultiReader(strings.NewReader(prefix), strings.NewReader(strings.Repeat("#\n", padding/2)), strings.NewReader(strings.Repeat("#", padding%2)))
			reader := &ingestCountingReader{Reader: input}
			fps, err := scanIngestSource("fixture.env", reader, []byte("salt"), 1)
			if size > maxIngestBytes {
				if err == nil || fps != nil {
					t.Errorf("oversized source returned %d fingerprints and error %v", len(fps), err)
				}
				if reader.bytesRead > maxIngestBytes+1 {
					t.Errorf("read %d bytes beyond budget %d", reader.bytesRead, maxIngestBytes+1)
				}
			} else if err != nil || len(fps) != 1 || fps[0].HMAC != Fingerprint([]byte("salt"), "first-fixture-value") {
				t.Errorf("source within limit: %d fingerprints, %v", len(fps), err)
			}
		})
	}
}

func TestIngestPreservesIDsAcrossSources(t *testing.T) {
	dir := t.TempDir()
	var sources []string
	for _, key := range []string{"FIRST", "SECOND"} {
		path := filepath.Join(dir, key+".env")
		if err := os.WriteFile(path, []byte(key+"=fixture-value-for-"+key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sources = append(sources, path)
	}
	fps, err := Ingest(sources, []byte("salt"))
	if err != nil || len(fps) != 2 || fps[0].ID != "fp-1" || fps[1].ID != "fp-2" {
		t.Fatalf("fingerprint identity across sources: %+v, %v", fps, err)
	}
}

func TestIngestFingerprintsWithoutStoringPlaintext(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	secret := "STRIPE-abcdef0123456789abcdef01"
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY="+secret+"\n# comment\nEMPTY=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fps, err := Ingest([]string{envPath}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fps) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(fps))
	}
	if fps[0].HMAC != Fingerprint([]byte("salt"), secret) {
		t.Fatal("fingerprint HMAC mismatch")
	}
	// The struct must not carry the raw secret anywhere.
	if fps[0].Label == secret || fps[0].ID == secret {
		t.Fatal("plaintext secret leaked into fingerprint metadata")
	}
}

func TestIngestRefusesEmptyResultWhenAllSourcesFail(t *testing.T) {
	// Persisting an empty set would silently purge every registered
	// fingerprint — the detection layer turns off while looking healthy.
	missing := filepath.Join(t.TempDir(), "unmounted-volume", ".env")
	fps, err := Ingest([]string{missing}, []byte("salt"))
	if err == nil {
		t.Fatal("expected error when every source failed and no fingerprints were produced")
	}
	if fps != nil {
		t.Fatalf("expected nil fingerprints on refusal, got %d", len(fps))
	}
}

func TestIngestZeroSourcesIsNotAnError(t *testing.T) {
	// No configured sources at all is a legitimate steady state, not a failure.
	fps, err := Ingest(nil, []byte("salt"))
	if err != nil {
		t.Fatalf("nil sources should not error: %v", err)
	}
	if len(fps) != 0 {
		t.Fatalf("expected 0 fingerprints, got %d", len(fps))
	}
}

func TestIngestRejectsPartialScans(t *testing.T) {
	for _, scenario := range []string{"valid-prefix", "healthy-source-first", "healthy-source-last"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			broken := filepath.Join(dir, "broken.env")
			healthy := filepath.Join(dir, "healthy.env")
			const value = "fixture-value-for-ingestion"
			content := strings.Repeat("x", maxIngestLineBytes+1) + "\nAFTER=" + value + "\n"
			sources := []string{broken}
			switch scenario {
			case "valid-prefix":
				content = "BEFORE=" + value + "\n" + content
			case "healthy-source-first":
				sources = []string{healthy, broken}
			case "healthy-source-last":
				sources = []string{broken, healthy}
			}
			if err := os.WriteFile(broken, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(healthy, []byte("HEALTHY="+value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fps, err := Ingest(sources, []byte("salt"))
			if err == nil || fps != nil {
				t.Fatalf("partial scan returned %d fingerprints and error %v", len(fps), err)
			}
			if !strings.Contains(err.Error(), broken) || strings.Contains(err.Error(), value) {
				t.Fatalf("scan error must identify the source without its value: %v", err)
			}
		})
	}
}

func TestIngestAllowsMissingOptionalSource(t *testing.T) {
	dir := t.TempDir()
	healthy := filepath.Join(dir, "healthy.env")
	if err := os.WriteFile(healthy, []byte("FIXTURE=fixture-value-for-ingestion\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fps, err := Ingest([]string{filepath.Join(dir, "missing.env"), healthy}, []byte("salt"))
	if err != nil || len(fps) != 1 {
		t.Fatalf("missing optional source prevented healthy ingestion: %d fingerprints, %v", len(fps), err)
	}
}

func TestIngestRejectsDeviceSources(t *testing.T) {
	healthy := filepath.Join(t.TempDir(), "healthy.env")
	if err := os.WriteFile(healthy, []byte("FIXTURE=fixture-value-for-ingestion\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sources := range [][]string{{os.DevNull}, {healthy, os.DevNull}, {os.DevNull, healthy}} {
		fps, err := Ingest(sources, []byte("salt"))
		if err == nil || fps != nil {
			t.Errorf("device source returned %d fingerprints and error %v", len(fps), err)
		}
	}
}
