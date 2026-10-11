package fleet

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeliveryLogRotationFailurePreservesHistoryAndRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webhook-deliveries.jsonl")
	seed := append(bytes.Repeat([]byte(" "), testDeliveryLogBudget-3), []byte("{}\n")...)
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".1", 0700); err != nil {
		t.Fatal(err)
	}
	s := NewSink(WebhookConfig{URL: "https://example.invalid", Secret: "[REDACTED]"}, "n", "v", dir)
	s.record(EventFlag, "https://example.invalid/first", 200, "")
	before, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, seed) {
		t.Fatal("failed rotation changed retained history")
	}
	if err := os.Remove(path + ".1"); err != nil {
		t.Fatal(err)
	}
	s.record(EventFlag, "https://example.invalid/retry", 200, "")
	after, err := os.ReadFile(path)
	var rec struct {
		URL string `json:"url"`
	}
	if err != nil || json.Unmarshal(after, &rec) != nil || rec.URL != "https://example.invalid/retry" {
		t.Fatalf("rotation did not recover: %v", err)
	}
	backup, err := os.ReadFile(path + ".1")
	if err != nil || !bytes.Equal(backup, seed) {
		t.Fatal("rotation recovery did not preserve prior generation")
	}
}
