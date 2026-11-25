package report

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestMemoryPresenterStructuredSummaries(t *testing.T) {
	known := PresentMemoryFact(store.MemoryFact{Kind: "guard", RuleID: "cloud-creds", Verdict: "allow", Scope: "always"})
	for _, want := range []string{"Cloud credentials", "Allow", "Always"} {
		if !strings.Contains(known.Title+" "+known.Detail, want) {
			t.Fatalf("known guard summary missing %q: %+v", want, known)
		}
	}
	unknown := PresentMemoryFact(store.MemoryFact{Kind: "guard", RuleID: "PRIVATE_PROMPT_TEXT123", Verdict: "allow", Scope: "PRIVATE_SCOPE123"})
	if strings.Contains(fmt.Sprintf("%+v", unknown), "PRIVATE_") || !strings.Contains(unknown.Detail, "Guard rule") || strings.Contains(unknown.Detail, "Scope:") {
		t.Fatalf("unknown guard fields leaked or lost generic label: %+v", unknown)
	}
	once := PresentMemoryFact(store.MemoryFact{Kind: "guard", RuleID: "cloud-creds", Verdict: "allow", Scope: "once"})
	if !strings.Contains(once.Detail, "Scope: Once") || once.Detail == known.Detail {
		t.Fatalf("allow-once and allow-always summaries are indistinguishable: once=%+v always=%+v", once, known)
	}
	resource := PresentMemoryFact(store.MemoryFact{Kind: "resource", DiagnosisCodes: []string{"heavy-memory"}, RSSBytes: 4 << 30})
	if !strings.Contains(resource.Detail, "Heavy memory") || !strings.Contains(resource.Detail, "4 GiB") {
		t.Fatalf("resource summary lost measured pressure: %+v", resource)
	}
	usage := PresentMemoryFact(store.MemoryFact{Kind: "activity", EventKind: event.KindModelCall, Model: "claude-sonnet-4-5", TokensIn: 1200, TokensOut: 300})
	for _, want := range []string{"1200 input", "300 output"} {
		if !strings.Contains(usage.Detail, want) {
			t.Fatalf("usage summary missing %q: %+v", want, usage)
		}
	}
	big := PresentMemoryFact(store.MemoryFact{Kind: "resource", RSSBytes: math.MaxUint64})
	if !strings.Contains(big.Detail, "15.9 EiB") || strings.Contains(big.Detail, "-") {
		t.Fatalf("large RSS overflowed or disappeared: %+v", big)
	}
	bigUsage := PresentMemoryFact(store.MemoryFact{Kind: "activity", EventKind: event.KindModelCall, TokensIn: math.MaxInt64, TokensOut: -1})
	if !strings.Contains(bigUsage.Detail, "9223372036854775807 input") || strings.Contains(bigUsage.Detail, "-1") {
		t.Fatalf("usage counts overflowed or exposed negative value: %+v", bigUsage)
	}
}

func TestMemorySourceReferences(t *testing.T) {
	for _, tc := range []struct {
		kind, sourceID, want string
	}{
		{"flag", "finding-123", "finding-123"},
		{"incident", "incident-123", "incident-123"},
		{"flag", "", ""},
		{"flag", "<script>private</script>", ""},
		{"incident", strings.Repeat("a", 129), ""},
		{"activity", "event-123", ""},
		{"guard-audit", "event-123", ""},
		{"guard", "decision-123", ""},
		{"resource", "123", ""},
		{"unknown", "finding-123", ""},
	} {
		t.Run(tc.kind+"/"+tc.sourceID, func(t *testing.T) {
			row := PresentMemoryFact(store.MemoryFact{ID: tc.kind + ":display-id", Kind: tc.kind, SourceID: tc.sourceID})
			var wire map[string]any
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if _, present := wire["source_id"]; present {
					t.Fatalf("unsupported or invalid source exposed: %s", data)
				}
			} else if wire["source_id"] != tc.want {
				t.Fatalf("source_id = %v, want %q (never the display ID)", wire["source_id"], tc.want)
			}
		})
	}
}

func TestMemoryRSSLabelFractionBoundary(t *testing.T) {
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{{1126, "1.0 KiB"}, {1127, "1.1 KiB"}} {
		if got := memoryRSSLabel(tc.bytes); got != tc.want {
			t.Errorf("memoryRSSLabel(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}
