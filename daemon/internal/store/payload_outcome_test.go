package store

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestPayloadOutcomeSurvivesRestartAndMixedIncidentAggregation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var incidentID string
	for i, action := range []string{"block", "would-block", ""} {
		var flag model.Flag
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"id":"flag-%d","rule":"proxy-secret-leak","severity":3,"evidence":[{"kind":"violation","sub":"payload inspection","payload":{"layer":"pattern","field":"body","verdict":"leak","finding_action":%q,"request_action":%q}}]}`, i, action, action)), &flag); err != nil {
			t.Fatal(err)
		}
		flag.TS = now.Add(time.Duration(i) * time.Second)
		if _, err := s.PutFlag(flag); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			report := intel.NewAnalyzer().Analyze(flag, nil)
			incidentID = report.ID
			if err := s.PutIncident(report); err != nil {
				t.Fatal(err)
			}
		} else if _, ok := s.AggregateIntoIncident(incidentID, flag.ID, flag.TS); !ok {
			t.Fatal("aggregation failed")
		}
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	flag, ok := s.GetFlag("flag-0")
	if !ok || model.AssessFinding(flag).Control != "blocked" {
		t.Fatalf("stored outcome lost: %+v", flag)
	}
	report, err := s.GetIncident(incidentID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Outcomes *struct {
			Blocked  int `json:"blocked"`
			Observed int `json:"observed_only"`
			Unknown  int `json:"unknown"`
		} `json:"payload_outcomes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Outcomes == nil || decoded.Outcomes.Blocked != 1 || decoded.Outcomes.Observed != 1 || decoded.Outcomes.Unknown != 1 {
		t.Fatalf("mixed outcomes collapsed: %s", raw)
	}
	// A delivery retry cannot count the same source twice.
	if _, ok := s.AggregateIntoIncident(incidentID, "flag-1", now); !ok {
		t.Fatal("idempotent aggregate failed")
	}
	after, err := s.GetIncident(incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if after.AggregateCount != 3 {
		t.Fatalf("duplicate inflated count: %d", after.AggregateCount)
	}
}
