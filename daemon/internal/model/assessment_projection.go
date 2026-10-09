package model

import (
	"slices"
	"time"
)

// assessmentForFlag reads producer-owned fields only. Neither legacy display
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
