package intel

import (
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/testvalue"
)

func TestTranscriptLowEntropyReviewRisk(t *testing.T) {
	for _, tc := range []struct {
		name, layer string
		signals     []string
		severity    int
		extra       bool
		want        model.RiskLevel
	}{
		{"test code", "pattern", []string{testvalue.LowEntropy, testvalue.TestCode}, 2, false, model.RiskMedium},
		{"test file", "pattern", []string{testvalue.LowEntropy, testvalue.TestFile + " (live_test.py)", testvalue.DummyWording}, 2, false, model.RiskMedium},
		{"low entropy alone", "pattern", []string{testvalue.LowEntropy}, 2, false, model.RiskHigh},
		{"filename alone", "pattern", []string{testvalue.TestFile + " (live_test.py)"}, 2, false, model.RiskHigh},
		{"vague wording", "pattern", []string{testvalue.LowEntropy, testvalue.DummyWording}, 2, false, model.RiskHigh},
		{"live-looking in tests", "pattern", []string{testvalue.TestCode, testvalue.DummyWording}, 2, false, model.RiskHigh},
		{"unknown evidence", "pattern", []string{testvalue.LowEntropy, testvalue.TestCode, "unrecognized reason"}, 2, false, model.RiskHigh},
		{"incomplete filename evidence", "pattern", []string{testvalue.LowEntropy, testvalue.TestFile}, 2, false, model.RiskHigh},
		{"mixed evidence", "pattern", []string{testvalue.LowEntropy, testvalue.TestCode}, 2, true, model.RiskHigh},
		{"registered secret", "fingerprint", []string{testvalue.LowEntropy, testvalue.TestCode}, 3, false, model.RiskCritical},
		{"critical evidence", "pattern", []string{testvalue.LowEntropy, testvalue.TestCode}, 3, false, model.RiskCritical},
		{"missing evidence", "pattern", nil, 2, false, model.RiskHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := model.Flag{Rule: "secret-in-transcript", Severity: tc.severity,
				Evidence: []model.EvidenceItem{{Kind: "transcript", Label: "/sessions/s.jsonl", Rule: "db", Sub: tc.layer + " match"},
					{Kind: "test-value", Sub: strings.Join(tc.signals, "; ")}}}
			if tc.extra {
				f.Evidence = append(f.Evidence, model.EvidenceItem{Kind: "transcript", Label: "/sessions/s.jsonl", Rule: "other", Sub: "pattern match"})
			}
			if got := NewAnalyzer().Analyze(f, nil).Risk; got != tc.want {
				t.Fatalf("report risk = %s, want %s", got, tc.want)
			}
			if tc.want == model.RiskMedium && model.AssessFinding(f).Risk != "review" {
				t.Fatal("report and finding review priority disagree")
			}
		})
	}
}
