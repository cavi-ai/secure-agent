package pattern

import (
	"fmt"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/report"
)

// RoutineArea keys a read path: the home dot-directory it sits under
// (~/.docker), else the file itself.
func RoutineArea(path, home string) string {
	if home != "" && strings.HasPrefix(path, home+"/.") {
		if dir, _, found := strings.Cut(path[len(home)+1:], "/"); found {
			return home + "/" + dir
		}
	}
	return path
}

// ReaderOf is the reader label an expectation keys a read by; empty when
// the read recorded no process.
func ReaderOf(read model.EvidenceItem) string {
	tool := read.Sub == "agent tool read"
	if read.Exe == "" && !tool {
		return ""
	}
	return correlate.ReaderLabel(read.Exe, tool)
}

// RoutineDestinations names the busiest two destinations (org, else host):
// "GitHub", "Google and Cloudflare", "GitHub, Google and 4 more".
func RoutineDestinations(dests []model.PatternDestination, total int) string {
	var names []string
	for _, d := range dests {
		if len(names) == 2 {
			break
		}
		names = append(names, report.FirstNonEmpty([]string{d.Org, d.Host}))
	}
	switch {
	case len(names) == 0:
		return "an outside host"
	case total > len(names):
		return fmt.Sprintf("%s and %d more", strings.Join(names, ", "), total-len(names))
	default:
		return strings.Join(names, " and ")
	}
}
