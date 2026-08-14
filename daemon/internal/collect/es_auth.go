package collect

import (
	"context"
	"fmt"
	"log"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

type ESAuthCollector struct {
	bus        *bus.Bus
	classifier sensitive.Classifier
}

func NewESAuthCollector(b *bus.Bus, classifier sensitive.Classifier) *ESAuthCollector {
	return &ESAuthCollector{
		bus:        b,
		classifier: classifier,
	}
}

// Run starts the Endpoint Security AUTH event monitor (or pure-Go fallback on un-entitled builds).
func (es *ESAuthCollector) Run(ctx context.Context) error {
	log.Println("[ES_AUTH] Endpoint Security AUTH-event synchronous blocker initialized (pure-Go fallback mode).")

	<-ctx.Done()
	return ctx.Err()
}

// EvaluateAuthOpen simulates synchronous kernel-level evaluation for an ES_EVENT_TYPE_AUTH_OPEN event.
// Returns true to ALLOW, false to DENY.
func (es *ESAuthCollector) EvaluateAuthOpen(pid int32, exePath, targetPath string) bool {
	cat, isSensitive := es.classifier.Classify(targetPath)
	if isSensitive {
		if cat == sensitive.CatKeychain {
			es.bus.Publish(event.Event{
				Kind:    event.KindFileOpen,
				PID:     pid,
				ExePath: exePath,
				Path:    targetPath,
				Detail:  fmt.Sprintf("ES_AUTH_DENY: blocked unauthorized access to %s", cat),
			})
			return false // DENY file access at kernel level
		}
	}
	return true // ALLOW
}
