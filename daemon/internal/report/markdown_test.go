package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestRenderSessionMarkdownTruncates(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.Local)
	rep := store.SessionReport{
		Session:  model.Session{ID: "s9", Harness: "claude", Repo: "A", Status: "ended", Confidence: "hook", StartedAt: start},
		Events:   150,
		CostUSD:  0.004,
		Unpriced: 2,
		Models:   []store.ReportModel{{Model: "m|x", Calls: 2, Unpriced: 2}},
	}
	for i := 0; i < store.ReportTopN; i++ {
		rep.Files = append(rep.Files, store.ReportCount{Key: fmt.Sprintf("/w/f%02d", i), Count: 1})
	}
	for i := 0; i < 150; i++ {
		rep.Timeline = append(rep.Timeline, store.ReportLine{TS: start.Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339), Kind: "file-open", Label: "/w/f"})
	}
	md := SessionMarkdown(rep)
	for _, want := range []string{
		"# claude · A — 2026-09-01 10:00 → live (0s)\n",
		"cost <$0.01 (2 unpriced)",
		"Files touched 50+ ·",
		"| m\\|x | 2 | 0 | 0 | unpriced |",
		"- `/w/f24` × 1\n- … 25 more\n",
		"- 10:01:39 file-open /w/f\n- … 50 more\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("md missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "10:01:40") {
		t.Error("timeline must stop at 100 lines")
	}
	for in, want := range map[int64]string{0: "0ms", 850: "850ms", 1500: "1.5s", 125000: "2m 5s", 7380000: "2h 3m"} {
		if got := fmtMs(in); got != want {
			t.Errorf("fmtMs(%d) = %q, want %q", in, got, want)
		}
	}
}
