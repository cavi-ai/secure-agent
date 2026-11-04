package intel

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestUntrustedEgressRiskUsesTheRecordedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, decision string
		severity       int
		injected       bool
		credential     bool
		want           model.RiskLevel
	}{
		{"allowed tool output", "allowed", 1, false, false, model.RiskLow},
		{"blocked tool output", "denied", 1, false, false, model.RiskLow},
		{"monitored tool output", "monitored", 2, false, false, model.RiskMedium},
		{"matched injection", "monitored", 3, true, false, model.RiskHigh},
		{"credential evidence", "allowed", 1, false, true, model.RiskCritical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := model.Flag{ID: "tool-send", Rule: "untrusted-egress", Severity: tc.severity, TS: time.Now(),
				Evidence: []model.EvidenceItem{
					{Kind: "untrusted-input", Rule: "mcp", Label: "MCP tool output: workspace-tools"},
					{Kind: "send", Rule: tc.decision, Label: "git push origin"},
				}}
			if tc.injected {
				f.Evidence = append(f.Evidence, model.EvidenceItem{Kind: "untrusted-input", Rule: "injection", Label: "matched instructions"})
			}
			if tc.credential {
				f.Evidence = append(f.Evidence, model.EvidenceItem{Kind: "read", Label: "/work/repo/.env"})
			}
			report := NewAnalyzer().Analyze(f, nil)
			if report.Risk != tc.want {
				t.Fatalf("incident risk = %s, want %s", report.Risk, tc.want)
			}
		})
	}
}
