package correlate

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestConstructorHooksApplyBeforeFirstObservation(t *testing.T) {
	base := newFamilyCorrelator(t)
	c := New(base.tagger, base.classifier, base.cfg, Hooks{Expected: func(_ []string, _ time.Time) bool { return true }})
	at := time.Unix(1_700_000_000, 0)
	ghReads(c, t, event.KindFileOpen, at)
	if flags := connectTo(c, 201, "evil.example.com", at.Add(time.Second)); len(flags) != 0 {
		t.Fatalf("constructor hook not applied: %+v", flags)
	}
	if c.ExpectedCount() != 1 {
		t.Fatalf("expected count = %d", c.ExpectedCount())
	}
}
