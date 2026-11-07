package intel

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestTranscriptPatternIsNotAutomaticallyCritical(t *testing.T) {
	for _, tc := range []struct {
		severity int
		want     model.RiskLevel
	}{{2, model.RiskHigh}, {3, model.RiskCritical}} {
		report := NewAnalyzer().Analyze(model.Flag{Rule: "secret-in-transcript", Severity: tc.severity}, nil)
		if report.Risk != tc.want {
			t.Errorf("severity %d report risk %s, want %s", tc.severity, report.Risk, tc.want)
		}
	}
}
