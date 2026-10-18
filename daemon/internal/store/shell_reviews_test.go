package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/shellreview"
)

func TestShellReviewsPersistSeparatelyFromPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviews.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	r := shellreview.Result{ID: "observation-1", At: time.Now(), Mode: "observe", Choice: "review", GuardVerdict: "allow"}
	if err := s.PutShellReview(r); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.RecentShellReviews(10)
	if err != nil || len(got) != 1 || got[0].ID != r.ID || got[0].Choice != "review" {
		t.Fatalf("observations: %+v %v", got, err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM guard_decisions").Scan(&count); err != nil || count != 0 {
		t.Fatalf("observation became permission: %d %v", count, err)
	}
	if _, err := s.db.Exec("DROP TABLE shell_reviews"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecentShellReviews(10); err == nil {
		t.Fatal("read failure hidden")
	}
	if err := s.PutShellReview(r); err == nil {
		t.Fatal("write failure hidden")
	}
	h := s.WriteHealth()
	if !strings.Contains(strings.Join(h.Active, ","), "shell reviews") || !strings.Contains(strings.Join(h.ReadActive, ","), "shell reviews") {
		t.Fatalf("missing health: %+v", h)
	}
}
