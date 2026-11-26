package wiregen

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func swiftMirrorPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "menubar", "Sources", "SecureAgentMenubar", "Models.swift")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("Swift mirror not found at %s: %v", path, err)
	}
	return path
}

// swiftStruct extracts the declaration block for `public struct <name>`.
func swiftStruct(src, name string) string {
	re := regexp.MustCompile(`(?s)public struct ` + regexp.QuoteMeta(name) + `\b.*?\n\}`)
	return re.FindString(src)
}

// swiftCodingKeys extracts only the CodingKeys enum block — the sole place
// JSON key literals live. Scanning the whole struct body would match computed
// property literals (e.g. `kind == "infra"`) as if they were wire keys.
func swiftCodingKeys(structBlock string) string {
	re := regexp.MustCompile(`(?s)enum CodingKeys:[^\{]*\{(.*?)\n\s*\}`)
	m := re.FindStringSubmatch(structBlock)
	if m == nil {
		return ""
	}
	return m[1]
}

// swiftKeyLiteralRe finds snake_case JSON key literals in a CodingKey block.
var swiftKeyLiteralRe = regexp.MustCompile(`=\s*"([a-z0-9_]+)"`)

// TestSwiftWireNoInventedKeys is the drift tripwire: every JSON key a Swift
// mirror declares must exist on the Go type it mirrors. A renamed or removed
// Go field leaves a stale Swift key — which decodes as nil forever and is
// exactly how the app silently lost the P2 trace and aggregation fields.
func TestSwiftWireNoInventedKeys(t *testing.T) {
	src, err := os.ReadFile(swiftMirrorPath(t))
	if err != nil {
		t.Fatal(err)
	}
	mirror := string(src)

	// Only types the menubar actually decodes. A Swift mirror may declare a
	// subset of the Go keys (JSONDecoder ignores the rest) — that is fine and
	// not checked here; what is checked is that nothing it DECLARES is wrong.
	mapped := map[string]struct {
		swiftName string
		value     any
	}{
		"event.Event":                   {"EventModel", event.Event{}},
		"model.Flag":                    {"FlagModel", model.Flag{}},
		"model.FlagExplain":             {"FlagExplain", model.FlagExplain{}},
		"model.FindingAssessment":       {"FindingAssessmentModel", model.FindingAssessment{}},
		"model.IncidentReport":          {"IncidentReportModel", model.IncidentReport{}},
		"model.IncidentRemediation":     {"IncidentRemediationModel", model.IncidentRemediation{}},
		"model.IncidentRemediationStep": {"IncidentRemediationStepModel", model.IncidentRemediationStep{}},
		"model.AdvisorVerdict":          {"AdvisorVerdictModel", model.AdvisorVerdict{}},
		"api.Status":                    {"StatusResponse", api.Status{}},
		"api.AgentSummary":              {"AgentSummaryModel", api.AgentSummary{}},
		"api.CoverageStatus":            {"CoverageModel", api.CoverageStatus{}},
		"supervise.Health":              {"HealthModel", supervise.Health{}},
		"advisor.Health":                {"AdvisorHealthModel", advisor.HealthSnapshot{}},
		"firewall.RuleStat":             {"RuleStatModel", firewall.RuleStat{}},
		"resource.Session":              {"ResourceSessionModel", resource.Session{}},
		"model.InterventionReceipt":     {"ResourceOutcomeModel", model.InterventionReceipt{}},
	}

	for goName, m := range mapped {
		block := swiftStruct(mirror, m.swiftName)
		if block == "" {
			t.Errorf("%s: Swift mirror %s not found in Models.swift", goName, m.swiftName)
			continue
		}
		valid := map[string]bool{}
		for _, k := range JSONKeys(m.value) {
			valid[k] = true
		}
		declared := map[string]bool{}
		for _, m2 := range swiftKeyLiteralRe.FindAllStringSubmatch(swiftCodingKeys(block), -1) {
			declared[m2[1]] = true
		}
		for k := range declared {
			if !valid[k] {
				t.Errorf("%s → %s declares JSON key %q that the Go type does not emit (stale or invented)",
					goName, m.swiftName, k)
			}
		}
	}
}
