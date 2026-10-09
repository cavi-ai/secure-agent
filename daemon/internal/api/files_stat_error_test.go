package api

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFileActionsDistinguishStatFailureFromDeletedFile(t *testing.T) {
	st := testStore(t)
	defer st.Close()
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	rec := &openRecorder{}
	a.openPath = rec.open
	p := filepath.Join(t.TempDir(), "evidence.jsonl")
	if err := os.Symlink(p, p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutFlag(model.Flag{ID: "f1", TS: time.Now(), Evidence: []model.EvidenceItem{{Label: p}}}); err != nil {
		t.Fatal(err)
	}
	actions := []func(http.ResponseWriter, *http.Request){a.handleFileOpen, a.handleFileReveal}
	for _, h := range actions {
		if w := postFile(a, h, http.MethodPost, p); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unreadable file: %d %s", w.Code, w.Body.String())
		}
	}
	if len(rec.calls) != 0 || len(st.RecentAudit(10)) != 0 {
		t.Errorf("stat failure ran or recorded a file action: %v", rec.calls)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, h := range actions {
		if w := postFile(a, h, http.MethodPost, p); w.Code != http.StatusOK {
			t.Fatalf("recovered file: %d %s", w.Code, w.Body.String())
		}
	}
	if len(rec.calls) != 2 || len(st.RecentAudit(10)) != 2 {
		t.Fatalf("recovered actions missing: %v", rec.calls)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	for _, h := range actions {
		if w := postFile(a, h, http.MethodPost, p); w.Code != http.StatusGone {
			t.Fatalf("deleted file: %d %s", w.Code, w.Body.String())
		}
	}
	if len(rec.calls) != 2 || len(st.RecentAudit(10)) != 2 {
		t.Fatalf("deleted file ran or recorded an action: %v", rec.calls)
	}
}
