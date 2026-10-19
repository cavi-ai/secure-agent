package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestCollectorPermissionFailureOverridesFreshSpoolAndGrace(t *testing.T) {
	now := time.Now().UTC()
	var es collect.ESServiceSnapshot
	data := `{"state":"running","collector":{"state":"permission_denied","updated_at":"` + now.Format(time.RFC3339Nano) + `"}}`
	if err := json.Unmarshal([]byte(data), &es); err != nil {
		t.Fatal(err)
	}
	es.SpoolMtime = now
	items := esServiceItems(now, es)
	if len(items) != 1 || !strings.Contains(items[0].Detail, "Full Disk Access") {
		t.Fatalf("permission denial hidden behind parent liveness: %+v", items)
	}
	state, detail := checkFileTelemetry(doctorFacts{st: Status{ESService: &es}, now: now, grace: true})
	if state != doctorFail || !strings.Contains(detail, "Full Disk Access") {
		t.Fatalf("doctor hides permission denial: %s %s", state, detail)
	}
	es.Collector.UpdatedAt = now.Add(-2 * time.Minute)
	if items := esServiceItems(now, es); len(items) != 0 {
		t.Fatalf("stale authorization status remained current: %+v", items)
	}
}

func TestStorageReadDiagnosticsAppearInDoctorAndPosture(t *testing.T) {
	now := time.Now().UTC()
	health := &store.WriteHealth{ReadFailures: 1, ReadActive: []string{"session report events"}, ReadIssues: []store.ReadIssue{{Operation: "session report events", Category: "deadline", Failures: 1, FirstFailureAt: now, LastFailureAt: now}}}
	status := Status{StorageHealth: health}
	_, detail := checkStorage(doctorFacts{st: status})
	if !strings.Contains(detail, "deadline") || !strings.Contains(detail, now.Format(time.RFC3339)) {
		t.Fatalf("doctor omitted diagnostic: %s", detail)
	}
	items := machineAttentionItems(now, status, nil)
	for _, item := range items {
		if item.Kind == "storage_read_failure" {
			if !strings.Contains(item.Detail, "deadline") || !strings.Contains(item.Detail, now.Format(time.RFC3339)) {
				t.Fatalf("posture omitted diagnostic: %+v", item)
			}
			return
		}
	}
	t.Fatal("posture omitted read failure")
}
