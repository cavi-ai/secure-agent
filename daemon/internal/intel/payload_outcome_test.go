package intel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentReportsRecordedPayloadOutcomeWithoutClaimingRemediation(t *testing.T) {
	var flag model.Flag
	if err := json.Unmarshal([]byte(`{"id":"fixture","rule":"proxy-secret-leak","severity":3,"evidence":[{"kind":"violation","sub":"payload inspection","payload":{"layer":"fingerprint","field":"body","verdict":"leak","finding_action":"block","request_action":"block"}}]}`), &flag); err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer()
	report := a.Analyze(flag, nil)
	md := a.GenerateMarkdown(report)
	if !strings.Contains(md, "1 blocked before forwarding") || !strings.Contains(md, "recorded findings") || !strings.Contains(md, "Earlier exposure") {
		t.Fatalf("incident omitted bounded control result: %s", md)
	}
}

func TestUnattributedProxyFindingDoesNotBorrowOtherProcessesCredentials(t *testing.T) {
	now := time.Now()
	f := model.Flag{ID: "proxy", Rule: "proxy-secret-leak", TS: now, Severity: 3}
	report := NewAnalyzer().Analyze(f, []event.Event{
		{Kind: event.KindFileOpen, PID: 200, TS: now, Path: "/workspace/.aws/credentials"},
		{Kind: event.KindConnOpen, PID: 200, TS: now, RemoteHost: "unrelated.invalid", RemotePort: 443},
	})
	if len(report.TouchedFiles) != 0 || len(report.RotateList) != 0 || len(report.Connections) != 0 {
		t.Fatalf("invented proxy attribution: %+v", report)
	}
}

func TestHistoricalPayloadReportLeavesEveryControlOutcomeUnknown(t *testing.T) {
	report := model.IncidentReport{Rule: "proxy-secret-leak", AggregateCount: 3, Summary: "Historical record said blocked."}
	md := NewAnalyzer().GenerateMarkdown(report)
	if !strings.Contains(md, "3 outcome unknown") || !strings.Contains(md, "0 blocked before forwarding") {
		t.Fatalf("historical prose became control proof: %s", md)
	}
}
