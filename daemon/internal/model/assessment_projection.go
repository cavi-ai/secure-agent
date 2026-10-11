package model

import (
	"slices"
	"time"
)

// AssessFinding reads producer-owned fields only. Neither legacy display
// text nor an advisor verdict establishes payload contents or control results.
func AssessFinding(f Flag) FindingAssessment {
	a := FindingAssessment{
		DetectorSeverity: f.Severity,
		EvidenceBasis:    []string{}, Risk: "unknown", Control: "unknown", ResidualRisk: "unknown",
		ReviewState: "unreviewed", Reason: "The detector reported this finding; its evidence does not establish exposure or a control outcome.",
		Limits: []string{"A configured policy does not establish that this operation was blocked or allowed."}, Advice: f.Advisor,
	}
	if f.Acknowledged {
		a.ReviewState = "reviewed"
	}
	if f.Rule == "proxy-secret-leak" {
		for _, e := range f.Evidence {
			if e.Kind != "violation" || e.Sub != "payload inspection" || e.Payload == nil || !e.Payload.IsLeak() {
				continue
			}
			p := e.Payload
			a.EvidenceBasis = []string{p.Layer + "-payload"}
			a.Risk, a.ResidualRisk, a.Control = "critical", "transmission-attempt", "observed-only"
			match := "A typed secret pattern"
			if p.Layer == "fingerprint" {
				match = "A registered secret fingerprint"
			}
			field := map[string]string{"auth-header": "authorization header", "other-header": "header", "query": "query string", "body": "body"}[p.Field]
			a.Reason = match + " matched an inspected outbound request " + field + ". The local proxy observed this attempt without blocking it."
			a.Limits = []string{"This result covers this request at this local proxy. Earlier exposure and external credential revocation are not verified."}
			if p.RequestAction == "block" {
				a.Control = "blocked"
				a.Reason = match + " matched an inspected outbound request " + field + ". The local proxy rejected this request before forwarding."
				if p.FindingAction == "would-block" {
					a.Limits = append(a.Limits, "This match's rule was monitor-only; another match blocked the request.")
				}
			} else {
				a.Limits = append(a.Limits, "Monitor-only observation does not establish whether forwarding succeeded or the recipient accepted the request.")
			}
			if p.Layer == "pattern" {
				a.Limits = append(a.Limits, "A typed pattern match may be a false positive.")
			}
			return a
		}
	}
	var reads, conns []EvidenceItem
	for _, e := range f.Evidence {
		switch {
		case e.Kind == "text":
			a.EvidenceBasis = appendBasis(a.EvidenceBasis, "legacy-text")
		case f.Rule == "sensitive-read-then-connect" && e.Kind == "read" && e.Label != "" && (e.Sub == "sensitive read" || e.Sub == "agent tool read"):
			reads = append(reads, e)
		case f.Rule == "sensitive-read-then-connect" && e.Kind == "connect" && e.Sub == "egress" && e.Label != "":
			conns = append(conns, e)
		}
	}
	if len(reads) == 0 {
		a.Limits = append(a.Limits, "Legacy or unsupported evidence cannot establish a payload match. Inspect the recorded evidence.")
		return a
	}
	a.Risk, a.ResidualRisk, a.RecommendationID = "review", "possible-exposure", "inspect-file"
	a.Reason = "A sensitive file read was observed. Review its purpose and the nearby connections."
	a.Limits = append(a.Limits, "Read and connection timing does not establish that secret bytes were transmitted or identify the receiving service.")
	modelVisible, sameReader, sibling := false, false, false
	for _, r := range reads {
		if r.Sub == "agent tool read" {
			modelVisible = true
			a.EvidenceBasis = appendBasis(a.EvidenceBasis, "model-visible-read")
		} else {
			a.EvidenceBasis = appendBasis(a.EvidenceBasis, "os-read")
		}
		readAt, err := time.Parse(time.RFC3339Nano, r.TS)
		if err != nil || r.PID <= 0 {
			continue
		}
		for _, c := range conns {
			connAt, err := time.Parse(time.RFC3339Nano, c.TS)
			if err != nil || c.PID <= 0 || connAt.Before(readAt) {
				continue
			}
			// Match the detector's directional relation: the reader or its
			// descendant connected after reading. A common ancestor alone
			// cannot establish that the reader made the connection.
			if r.PID == c.PID || slices.Contains(c.Chain, r.PID) {
				sameReader = true
				a.EvidenceBasis = appendBasis(a.EvidenceBasis, "same-tree-connect")
			} else if !slices.Contains(r.Chain, c.PID) {
				for _, pid := range r.Chain {
					if pid > 0 && slices.Contains(c.Chain, pid) {
						sibling = true
						a.EvidenceBasis = appendBasis(a.EvidenceBasis, "sibling-connect")
						break
					}
				}
			}
		}
	}
	switch {
	case modelVisible:
		a.Risk, a.ResidualRisk = "critical", "model-exposure"
		a.Reason = "A sensitive file was read through an agent tool and became model-visible."
	case sameReader:
		a.Risk = "high"
		a.Reason = "The reader or its descendant connected after reading a sensitive file. Possible exposure needs review."
	case sibling:
		a.Reason = "Sibling processes read a sensitive file and connected nearby in time. This is a temporal lead."
	}
	return a
}

func appendBasis(basis []string, value string) []string {
	if !slices.Contains(basis, value) {
		return append(basis, value)
	}
	return basis
}

// StrongestFindingAssessment uses the same evidence order as stored reviews.
// Review state belongs to the whole group; it never weakens observed risk.
func StrongestFindingAssessment(flags []Flag) *FindingAssessment {
	var strongest *FindingAssessment
	open := false
	for _, f := range flags {
		a := AssessFinding(f)
		open = open || !f.Acknowledged
		if strongest == nil || findingAssessmentOutranks(*strongest, a) {
			strongest = &a
		}
	}
	if strongest != nil {
		if open {
			strongest.ReviewState = "unreviewed"
		} else {
			strongest.ReviewState = "reviewed"
		}
		strongest.Limits = append(strongest.Limits, "This assessment describes the strongest member; grouped activity does not establish shared intent.")
	}
	return strongest
}

// FindingAssessmentMerge couples the chosen facts to their evidence source.
// Changed excludes advice and workflow so neither creates an evidence revision.
type FindingAssessmentMerge struct {
	Assessment   FindingAssessment
	Changed      bool
	NextEvidence bool
}

// MergeFindingAssessment retains the strongest observed facts, including late
// arrivals. Advice, timestamps, count and workflow are not semantic evidence.
func MergeFindingAssessment(old, next FindingAssessment) FindingAssessmentMerge {
	basis := append(slices.Clone(old.EvidenceBasis), next.EvidenceBasis...)
	slices.Sort(basis)
	basis = slices.Compact(basis)
	chosen := old
	nextEvidence := findingAssessmentOutranks(old, next)
	if nextEvidence {
		chosen = next
	}
	if next.Control != "unknown" && next.Control != "" {
		chosen.Control = next.Control
	}
	changed := !slices.Equal(basis, old.EvidenceBasis) || chosen.Risk != old.Risk || chosen.ResidualRisk != old.ResidualRisk || chosen.Control != old.Control || next.DetectorSeverity > old.DetectorSeverity
	chosen.EvidenceBasis = basis
	chosen.Advice = nil
	chosen.DetectorSeverity = max(old.DetectorSeverity, next.DetectorSeverity)
	return FindingAssessmentMerge{Assessment: chosen, Changed: changed, NextEvidence: nextEvidence}
}

// GroupFindingSeverity ranks a finding for a grouped card. High and review
// share a rank. Review merge uses findingAssessmentRank, where high outranks
// review. An unknown assessment must not silently lower a detector's priority.
func GroupFindingSeverity(a FindingAssessment, detectorSeverity int) int {
	switch a.Risk {
	case "critical":
		return 3
	case "high", "review":
		return 2
	case "informational":
		return 1
	default:
		return max(a.DetectorSeverity, detectorSeverity)
	}
}

func findingAssessmentRank(a FindingAssessment) int {
	switch a.Risk {
	case "critical":
		return 4
	case "high":
		return 3
	case "review":
		return 2
	case "informational":
		return 1
	default:
		return a.DetectorSeverity
	}
}

func findingAssessmentOutranks(stored, next FindingAssessment) bool {
	nextRank, storedRank := findingAssessmentRank(next), findingAssessmentRank(stored)
	return nextRank > storedRank || (nextRank == storedRank && stored.Risk == "unknown" && next.Risk != "unknown")
}
