package advisor

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Opt-in probe uses a synthetic finding, never the operator's stored evidence.
func TestLocalAdvisorToolIntegration(t *testing.T) {
	endpoint := os.Getenv("SECURE_AGENT_TEST_ADVISOR_ENDPOINT")
	if endpoint == "" {
		t.Skip("set local model and classifier endpoints to run the integration probe")
	}
	s := New(Config{Enabled: true, Endpoint: endpoint, Model: os.Getenv("SECURE_AGENT_TEST_ADVISOR_MODEL"),
		Timeout: 120 * time.Second, ClassifierEndpoint: os.Getenv("SECURE_AGENT_TEST_CLASSIFIER_ENDPOINT")}, &scopedTestSink{})
	if s == nil || s.cfg.ClassifierEndpoint == "" {
		t.Fatal("local model and classifier endpoints are required")
	}
	ctx := context.WithValue(context.Background(), reviewScopeKey{}, task{kind: "flag", flag: model.Flag{ID: "integration-fixture", SessionID: "fixture-session"}})
	classified, err := s.classifyEvidence(ctx, "Synthetic fixture: a test harness read README.md twice. No credentials or network events.")
	if err != nil || !strings.Contains(classified, `"available":true`) {
		t.Fatalf("local classifier did not return a valid routing result: %s %v", classified, err)
	}
	answer, err := s.chat(ctx, `This is a synthetic tool integration test. Call inspect_session_activity and classify_current_evidence before answering. Then return only {"assessment":"suspicious","confidence":0.5,"rationale":"synthetic fixture"}.`, "Synthetic fixture: a test harness read README.md twice. No credentials or network events.", 512)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal([]byte(answer), &result) != nil || s.Health().ToolCalls < 2 {
		t.Fatalf("model did not complete the tool exchange: tools=%d final_json=%v", s.Health().ToolCalls, result != nil)
	}
	t.Logf("local classifier available; model completed %d scoped tool calls and returned JSON", s.Health().ToolCalls)
}
