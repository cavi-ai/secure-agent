package collect

import (
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/testvalue"
)

func TestTranscriptFixturePatterns(t *testing.T) {
	d, err := firewall.NewDetector([]config.PatternConfig{
		{ID: "db", Re: `postgres://\S+:\S+@\S+`},
		{ID: "sandbox", Re: `sk_test_[A-Za-z0-9]{24,}`},
	}, config.EntropyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	fixture := "postgres" + "://test:test@localhost/unit"
	live := "postgres" + "://service:R7qL4vZ9mK2pT5wX@db.internal/app"
	for _, tc := range []struct {
		name, line string
		want       int
	}{
		{"placeholder in test code", "test_example.py assert(\"" + fixture + "\")", 0},
		{"live-looking value in test code", "test_example.py assert(\"" + live + "\")", 1},
		{"mixed values in test code", "test_example.py assert(\"" + fixture + "\", \"" + live + "\")", 1},
		{"placeholder without fixture context", fixture, 1},
		{"weak real credential in test code", "test_example.py assert(\"postgres" + "://service:aaaaaa@db.internal/app\")", 1},
		{"sandbox credential in test code", "test_example.py assert(\"sk_test_" + "R7qL4vZ9mK2pT5wX3aB8cN6dQ1fG\")", 1},
		{"live URI followed by JSON fixture text", `test_example.py {"value":"` + live + `","note":"fixture"}`, 1},
		{"live URI with test database name", "test_example.py assert(\"" + live + "_test\")", 1},
		{"compact mixed URI array", `{"file":"test_example.py","values":["` + fixture + `","` + live + `"]}`, 1},
		{"encoded dummy query on live URI", "test_example.py " + live + "?application_name=dGVzdA done", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := NewTranscriptScanner(bus.New(8), nil)
			ts.TextScanner = patternScanner{d}
			hits := ts.scanLine(tc.line, "/sessions/s.jsonl", "codex", "s", 0)
			if len(hits) != tc.want {
				t.Fatalf("got %d hits, want %d", len(hits), tc.want)
			}
			if tc.name == "mixed values in test code" && testvalue.Strong(strings.Split(hits[0].TestSignals, "; ")) {
				t.Fatal("one placeholder incorrectly marks the live-looking match as a test value")
			}
		})
	}
}

func TestRegisteredSecretInFixtureStillFlags(t *testing.T) {
	secret := "registered-fixture-placeholder-00000000"
	salt := []byte("fixture-test-salt")
	engine, err := firewall.NewEngine(config.FirewallConfig{}, salt)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetFingerprints([]config.Fingerprint{{ID: "registered", HMAC: firewall.Fingerprint(salt, secret), Len: len(secret)}})
	ts := NewTranscriptScanner(bus.New(8), nil)
	ts.TextScanner = engine
	hits := ts.scanLine("test_example.py assert(\""+secret+"\")", "/sessions/s.jsonl", "codex", "s", 0)
	if len(hits) != 1 || hits[0].Detail != "codex:fingerprint:registered" {
		t.Fatalf("registered secret lost: %+v", hits)
	}
}

func TestTranscriptReviewDoesNotSuppressStrongerMatches(t *testing.T) {
	weak := "postgres" + "://service:aaaaaa@db.internal/app"
	live := "postgres" + "://service:R7qL4vZ9mK2pT5wX@db.internal/app"
	registered := "K8rM2vL9qZ4pT7wX3nB5cH6dJ1fG0sA"
	salt := []byte("transcript-escalation-test")
	engine, err := firewall.NewEngine(config.FirewallConfig{Patterns: []config.PatternConfig{{ID: "db", Re: `postgres://\S+:\S+@\S+`}}}, salt)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetFingerprints([]config.Fingerprint{{ID: "db", HMAC: firewall.Fingerprint(salt, registered), Len: len(registered)}})
	ts := NewTranscriptScanner(bus.New(8), nil)
	ts.TextScanner = engine
	if got := ts.scanLine("live_test.py assert(\""+weak+"\")", "/sessions/s.jsonl", "codex", "s", 0); len(got) != 1 {
		t.Fatalf("review candidate: got %d hits, want 1", len(got))
	}
	stronger := "live_test.py assert(\"" + live + "\", \"" + registered + "\")"
	hits := ts.scanLine(stronger, "/sessions/s.jsonl", "codex", "s", 100)
	pattern, fingerprint := false, false
	for _, hit := range hits {
		pattern = pattern || hit.Detail == "codex:pattern:db"
		fingerprint = fingerprint || hit.Detail == "codex:fingerprint:db"
	}
	if !pattern || !fingerprint {
		t.Fatalf("later stronger matches suppressed: pattern=%v fingerprint=%v", pattern, fingerprint)
	}
	if got := ts.scanLine(stronger, "/sessions/s.jsonl", "codex", "s", 200); len(got) != 0 {
		t.Fatalf("identical stronger repeat: got %d hits, want 0", len(got))
	}
}
