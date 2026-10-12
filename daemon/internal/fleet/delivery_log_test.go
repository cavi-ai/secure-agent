package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// Each generation has a five-MiB budget; the log is diagnostic history.
const testDeliveryLogBudget = 5 << 20

func TestDeliveryLogRotatesAtByteBudget(t *testing.T) {
	dir := t.TempDir()
	s := NewSink(WebhookConfig{URL: "https://example.invalid", Secret: "[REDACTED]"}, "n", "v", dir)
	path := filepath.Join(dir, "webhook-deliveries.jsonl")
	seed := append(bytes.Repeat([]byte(" "), testDeliveryLogBudget-3), []byte("{}\n")...)
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, seed, 0600); err != nil {
			t.Fatal(err)
		}
		s.record(EventFlag, fmt.Sprintf("https://example.invalid/%d", i), 200, "")
		active, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(active) > testDeliveryLogBudget {
			t.Fatalf("active log exceeds byte budget: %d", len(active))
		}
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(active, &rec); err != nil || rec.URL != fmt.Sprintf("https://example.invalid/%d", i) {
			t.Fatalf("latest record missing: %s %v", active, err)
		}
		backup, err := os.ReadFile(path + ".1")
		if err != nil || !bytes.Equal(backup, seed) {
			t.Fatalf("previous generation changed: bytes=%d err=%v", len(backup), err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("unbounded backup generations: %+v %v", entries, err)
	}
}

func TestDeliveryLogBoundsOversizedHistoryAndRecords(t *testing.T) {
	dir := t.TempDir()
	s := NewSink(WebhookConfig{URL: "https://example.invalid", Secret: "[REDACTED]"}, "n", "v", dir)
	path := filepath.Join(dir, "webhook-deliveries.jsonl")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), testDeliveryLogBudget+1), 0600); err != nil {
		t.Fatal(err)
	}
	s.record(EventGuard, "https://example.invalid/latest", 200, "")
	for _, name := range []string{path, path + ".1"} {
		if info, err := os.Stat(name); err == nil && info.Size() > testDeliveryLogBudget {
			t.Errorf("oversized generation retained: %s %d", name, info.Size())
		} else if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil || !json.Valid(before) {
		t.Fatalf("fresh record unavailable: %v", err)
	}
	s.record(EventFlag, "https://example.invalid", 500, string(bytes.Repeat([]byte("x"), testDeliveryLogBudget+1)))
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("oversized record displaced bounded diagnostic history")
	}
}

func TestDeliveryLogSerializesSinksAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webhook-deliveries.jsonl")
	seed := append(bytes.Repeat([]byte(" "), testDeliveryLogBudget-3), []byte("{}\n")...)
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := NewSink(WebhookConfig{URL: "https://example.invalid", Secret: "[REDACTED]"}, "n", "v", dir)
			s.record(EventFlag, fmt.Sprintf("https://example.invalid/%d", i), 200, "")
		}(i)
	}
	wg.Wait()
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, line := range bytes.Split(bytes.TrimSpace(active), []byte("\n")) {
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.URL == "" || seen[rec.URL] {
			t.Fatalf("invalid or repeated record after rotation: %v", err)
		}
		seen[rec.URL] = true
	}
	if len(seen) != 32 {
		t.Fatalf("concurrent records lost: %d", len(seen))
	}
}

func TestDeliveryLogFailureDoesNotPreventDeliveryAndRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webhook-deliveries.jsonl")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	s := NewSink(WebhookConfig{URL: srv.URL, Secret: "[REDACTED]"}, "n", "v", dir)
	s.Deliver(EventFlag, map[string]string{"id": "first"}, 0, "")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s.Deliver(EventFlag, map[string]string{"id": "retry"}, 0, "")
	data, err := os.ReadFile(path)
	if calls.Load() != 2 || err != nil || !json.Valid(data) {
		t.Fatalf("delivery/log recovery failed: calls=%d err=%v", calls.Load(), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private log mode: %v %v", info, err)
	}
}
