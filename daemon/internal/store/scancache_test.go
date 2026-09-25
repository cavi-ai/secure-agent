package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestScanCacheRoundTripsAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := st.ScanCache("worktrees.report"); ok {
		t.Fatal("empty cache answered")
	}
	at := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	st.PutScanCache("worktrees.report", []byte(`{"a":1}`), at)
	st.PutScanCache("worktrees.report", []byte(`{"a":2}`), at.Add(time.Minute))
	st.Close()

	st, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	body, got, ok := st.ScanCache("worktrees.report")
	if !ok || string(body) != `{"a":2}` || !got.Equal(at.Add(time.Minute)) {
		t.Fatalf("ScanCache = %q, %v, %v", body, got, ok)
	}
}
