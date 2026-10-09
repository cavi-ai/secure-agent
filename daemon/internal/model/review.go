package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// ReviewContext identifies an evidence context, never a permission scope.
type ReviewContext struct {
	Rule         string   `json:"rule"`
	SessionID    string   `json:"session_id,omitempty"`
	Workspace    string   `json:"workspace,omitempty"`
	Readers      []string `json:"readers"`
	Resources    []string `json:"resources"`
	Destinations []string `json:"destinations"`
	Attribution  string   `json:"attribution"`
	SourceID     string   `json:"source_id,omitempty"`
}

func ContextForReview(f Flag, reliableSession bool) ReviewContext {
	c := ReviewContext{Rule: f.Rule, SessionID: f.SessionID, Workspace: f.Workspace, Readers: []string{}, Resources: []string{}, Destinations: []string{}, Attribution: "stored-session"}
	for _, e := range f.Evidence {
		if e.Kind == "read" && e.Label != "" && e.PID > 0 && (e.Sub == "sensitive read" || e.Sub == "agent tool read") {
			c.Readers = append(c.Readers, fmt.Sprintf("%d:%s", e.PID, e.Exe))
			c.Resources = append(c.Resources, e.Label)
		}
		if e.Kind == "connect" && e.Sub == "egress" && e.Label != "" {
			c.Destinations = append(c.Destinations, e.Label)
		}
	}
	for _, v := range []*[]string{&c.Readers, &c.Resources, &c.Destinations} {
		slices.Sort(*v)
		*v = slices.Compact(*v)
	}
	if !reliableSession || f.Rule != "sensitive-read-then-connect" || len(c.Readers) == 0 || len(c.Resources) == 0 || len(c.Destinations) == 0 {
		c.Attribution = "source-only"
		c.SourceID = f.ID
	}
	return c
}

func (c ReviewContext) Key() string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ReviewEvidenceKey detects a stale projection after a source row changed but
// its best-effort review write failed. Workflow and repeat counts are excluded.
func ReviewEvidenceKey(f Flag, a FindingAssessment) string {
	basis := slices.Clone(a.EvidenceBasis)
	slices.Sort(basis)
	b, _ := json.Marshal(struct {
		Context                 ReviewContext
		Basis                   []string
		Risk, Control, Residual string
		Severity                int
	}{ContextForReview(f, true), basis, a.Risk, a.Control, a.ResidualRisk, f.Severity})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type ReviewDecisionRequest struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Action   string `json:"action"` // acknowledge | close_reported
}

type ReviewDecisionReceipt struct {
	ID       string    `json:"id"`
	Revision int64     `json:"revision"`
	Action   string    `json:"action"`
	At       time.Time `json:"at"`
	Source   string    `json:"source,omitempty"`
}

// ReviewRecord links source evidence and an operator receipt. It owns no
// payload, permission, incident report, or claim of verified remediation.
type ReviewRecord struct {
	ID                    string                 `json:"id"`
	Revision              int64                  `json:"revision"`
	Context               ReviewContext          `json:"context"`
	Agent                 string                 `json:"agent"`
	Severity              int                    `json:"severity"`
	PID                   int32                  `json:"pid"`
	Assessment            FindingAssessment      `json:"assessment"`
	ReviewState           string                 `json:"review_state"`
	ReviewedRevision      int64                  `json:"reviewed_revision,omitempty"`
	Decision              *ReviewDecisionReceipt `json:"decision,omitempty"`
	Count                 int                    `json:"count"`
	FirstSeen             time.Time              `json:"first_seen"`
	LastSeen              time.Time              `json:"last_seen"`
	LatestFlagID          string                 `json:"latest_flag_id"`
	EvidenceFlagID        string                 `json:"evidence_flag_id"`
	EvidenceFlagAvailable bool                   `json:"evidence_flag_available"`
	SourceIDs             []string               `json:"source_ids"`
	IncidentIDs           []string               `json:"incident_ids"`
	EvidenceAvailable     bool                   `json:"evidence_available"`
}
