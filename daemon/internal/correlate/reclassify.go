package correlate

import (
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// ReclassifiedReadReason is stored on the sensitive-read-then-connect flags
// the daemon acknowledges at start because their read no longer counts as a
// secret read.
const ReclassifiedReadReason = "reclassified at start: the file read is shell or harness config, not a secret"

// StaleReadFlagIDs returns the unacknowledged sensitive-read-then-connect
// flags whose read matched a glob the classifier no longer treats as
// sensitive (guard rules that protect a file from tampering but hold no
// secret, such as shell rc files and harness settings).
func StaleReadFlagIDs(flags []model.Flag, cl sensitive.Classifier) []string {
	var ids []string
	for _, f := range flags {
		if f.Rule != "sensitive-read-then-connect" || f.Acknowledged {
			continue
		}
		for _, ev := range f.Evidence {
			if ev.Kind != "read" {
				continue
			}
			if strings.HasPrefix(ev.Rule, "glob:") && ev.Label != "" {
				if _, still := cl.Match(ev.Label); !still {
					ids = append(ids, f.ID)
				}
			}
			break
		}
	}
	return ids
}
