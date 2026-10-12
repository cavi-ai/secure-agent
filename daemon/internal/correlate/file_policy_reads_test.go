package correlate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpectedListResultRetriesFailureWithoutResettingHits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected.json")
	if err := os.WriteFile(path, []byte(`[{"agent":"claude"},{"agent":true}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewExpectStore(path)
	key := ReadConnectKey("claude", "tool", "/synthetic/config", "api.example.com")
	if s.Has(key) {
		t.Fatal("failed load applied an exception")
	}
	if rows, err := s.ListResult(); err == nil || rows != nil {
		t.Fatalf("failed read: %+v %v", rows, err)
	}
	data := `[{"agent":"claude","reader":"tool","path":"/synthetic/config","dest":"api.example.com","created_at":"2026-10-01T00:00:00Z"}]`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if s.Has(key) || s.Match([]string{key}, time.Now()) {
		t.Fatal("event matching retried the cached failure")
	}
	if rows, err := s.ListResult(); err != nil || len(rows) != 1 || rows[0].Key != key {
		t.Fatalf("read after repair: %+v %v", rows, err)
	}
	at := time.Unix(100, 0).UTC()
	if !s.Match([]string{key}, at) {
		t.Fatal("repaired policy not active")
	}
	for i := 0; i < 2; i++ {
		rows, err := s.ListResult()
		if err != nil || len(rows) != 1 || rows[0].Hits != 1 || rows[0].LastSeen == nil || !rows[0].LastSeen.Equal(at) {
			t.Fatalf("read reset hit state: %+v %v", rows, err)
		}
	}
}

func TestMuteLoadResultRejectsPartialDecodeAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "muted.json")
	if err := os.WriteFile(path, []byte(`{"rule":["valid.example.com",true]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewMuteStore(path)
	if rows, err := s.LoadResult(); err == nil || rows != nil {
		t.Fatalf("failed read returned partial policy: %+v %v", rows, err)
	}
	if s.Muted("rule", "valid.example.com", "claude") {
		t.Fatal("partial policy applied a mute")
	}
	if err := os.WriteFile(path, []byte(`{"rule":["valid.example.com"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LoadResult()
	if err != nil || len(rows["rule"]) != 1 || rows["rule"][0].Host != "valid.example.com" || !s.Muted("rule", "valid.example.com", "claude") {
		t.Fatalf("read after repair: %+v %v", rows, err)
	}
}
