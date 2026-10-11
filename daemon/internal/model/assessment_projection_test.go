package model

import (
	"reflect"
	"testing"
)

func TestGroupFindingSeverityFoldsReviewBesideMergeRank(t *testing.T) {
	high := FindingAssessment{Risk: "high", DetectorSeverity: 1}
	review := FindingAssessment{Risk: "review", DetectorSeverity: 1}
	if GroupFindingSeverity(high, 0) != GroupFindingSeverity(review, 0) {
		t.Fatal("grouped cards split high and review")
	}
	if !findingAssessmentOutranks(review, high) || findingAssessmentOutranks(high, review) {
		t.Fatal("review merge no longer lets high outrank review")
	}
	if GroupFindingSeverity(FindingAssessment{Risk: "unknown", DetectorSeverity: 4}, 9) != 9 {
		t.Fatal("unknown group rank lowered the detector")
	}
}

func TestMergeFindingAssessmentKeepsFactsAndEvidenceTogether(t *testing.T) {
	old := FindingAssessment{Risk: "high", Control: "unknown", ResidualRisk: "possible-exposure", DetectorSeverity: 3,
		EvidenceBasis: []string{"os-read", "same-tree-connect"}, Reason: "same reader", ReviewState: "reviewed"}
	for _, tc := range []struct {
		name                string
		next                FindingAssessment
		risk, control       string
		changed, nextSource bool
	}{
		{"stronger late evidence", FindingAssessment{Risk: "critical", Control: "unknown", ResidualRisk: "model-exposure", EvidenceBasis: []string{"model-visible-read"}}, "critical", "unknown", true, true},
		{"weaker late evidence", FindingAssessment{Risk: "review", Control: "unknown", ResidualRisk: "possible-exposure", EvidenceBasis: old.EvidenceBasis}, "high", "unknown", false, false},
		{"control only", FindingAssessment{Risk: "high", Control: "blocked", ResidualRisk: "possible-exposure", EvidenceBasis: old.EvidenceBasis}, "high", "blocked", true, false},
		{"advice and review are not evidence", FindingAssessment{Risk: "high", Control: "unknown", ResidualRisk: "possible-exposure", EvidenceBasis: old.EvidenceBasis, ReviewState: "unreviewed", Advice: &AdvisorVerdict{Assessment: "benign"}}, "high", "unknown", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := MergeFindingAssessment(old, tc.next)
			if got.Assessment.Risk != tc.risk || got.Assessment.Control != tc.control || got.Changed != tc.changed || got.NextEvidence != tc.nextSource {
				t.Fatalf("merge = %+v", got)
			}
			if got.Assessment.DetectorSeverity != 3 || got.Assessment.Advice != nil {
				t.Fatalf("merge lost detector priority or promoted advice: %+v", got)
			}
			if !tc.nextSource && got.Assessment.Reason != old.Reason {
				t.Fatalf("weaker evidence replaced the explanation: %+v", got)
			}
		})
	}
}

func TestMergeFindingAssessmentPreservesUnknownPriorityAndKnownTies(t *testing.T) {
	unknown := FindingAssessment{Risk: "unknown", DetectorSeverity: 3}
	high := FindingAssessment{Risk: "high", DetectorSeverity: 3}
	review := FindingAssessment{Risk: "review", DetectorSeverity: 3}
	if got := MergeFindingAssessment(unknown, review); got.NextEvidence || got.Assessment.Risk != "unknown" {
		t.Fatalf("weaker evidence erased unknown detector priority: %+v", got)
	}
	if got := MergeFindingAssessment(unknown, high); !got.NextEvidence || got.Assessment.Risk != "high" {
		t.Fatalf("known equal-rank evidence did not replace unknown: %+v", got)
	}
	if got := MergeFindingAssessment(high, unknown); got.NextEvidence || got.Assessment.Risk != "high" {
		t.Fatalf("unknown evidence displaced known equal-rank evidence: %+v", got)
	}
}

func TestMergeFindingAssessmentRetainsAllBasisWithoutMutatingInputs(t *testing.T) {
	old := FindingAssessment{Risk: "critical", EvidenceBasis: []string{"os-read", "model-visible-read"}}
	next := FindingAssessment{Risk: "review", EvidenceBasis: []string{"os-read", "sibling-connect"}}
	got := MergeFindingAssessment(old, next)
	if !got.Changed || got.NextEvidence || !reflect.DeepEqual(got.Assessment.EvidenceBasis, []string{"model-visible-read", "os-read", "sibling-connect"}) {
		t.Fatalf("merge lost evidence basis: %+v", got)
	}
	got.Assessment.EvidenceBasis[0] = "changed"
	if !reflect.DeepEqual(old.EvidenceBasis, []string{"os-read", "model-visible-read"}) || !reflect.DeepEqual(next.EvidenceBasis, []string{"os-read", "sibling-connect"}) {
		t.Fatal("merge changed its source assessments")
	}
}

func TestStrongestFindingAssessmentEmptyAndUnknown(t *testing.T) {
	if got := StrongestFindingAssessment(nil); got != nil {
		t.Fatalf("empty group invented an assessment: %+v", got)
	}
	got := StrongestFindingAssessment([]Flag{{Severity: 1, Acknowledged: true}, {Severity: 3, Acknowledged: true}})
	if got.Risk != "unknown" || got.DetectorSeverity != 3 || got.ReviewState != "reviewed" || len(got.Limits) == 0 {
		t.Fatalf("unknown group lost detector priority or review state: %+v", got)
	}
}
