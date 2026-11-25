package pattern

import (
	"fmt"
	"sort"

	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/report"
)

// DestinationOf is a connect item's org from the endpoint identity table,
// its host when the org is unknown, and the host.
func DestinationOf(ev model.EvidenceItem) (dest, org, host string) {
	host, _ = report.SplitHostPort(ev.Label)
	org = hostid.IdentifyCached(host).Org
	return report.FirstNonEmpty([]string{org, host}), org, host
}

// Destinations counts the flags citing each destination (org, else
// host), busiest PatternListCap first.
func Destinations(flags []model.Flag) []model.PatternDestination {
	byDest := map[string]*model.PatternDestination{}
	for _, f := range flags {
		seen := map[string]bool{}
		for _, ev := range f.Evidence {
			if ev.Kind != "connect" {
				continue
			}
			dest, org, host := DestinationOf(ev)
			if host == "" || seen[dest] {
				continue
			}
			seen[dest] = true
			d := byDest[dest]
			if d == nil {
				d = &model.PatternDestination{Org: org, Host: host}
				byDest[dest] = d
			}
			d.Count++
		}
	}
	out := make([]model.PatternDestination, 0, len(byDest))
	for _, d := range byDest {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	return CapList(out, model.PatternListCap)
}

// Reader is the reader report.ReaderName gives for most of the flags,
// empty when none names one.
func Reader(flags []model.Flag) string {
	n := map[string]int{}
	for _, f := range flags {
		if name := report.ReaderName(report.EvidenceOfKind(f, "read"), f.Agent); name != "" {
			n[name]++
		}
	}
	best := ""
	for name, c := range n {
		if c > n[best] || (c == n[best] && name < best) {
			best = name
		}
	}
	return best
}

// destinationPhrase: "GitHub (140.82.114.6)", "evil.example.com", plus
// " and N more" for further destinations.
func destinationPhrase(dests []model.PatternDestination) string {
	if len(dests) == 0 {
		return "an outside host"
	}
	d := dests[0]
	s := d.Host
	if d.Org != "" {
		s = d.Org + " (" + d.Host + ")"
	}
	if more := len(dests) - 1; more > 0 {
		s += fmt.Sprintf(" and %d more destination%s", more, Plural(more))
	}
	return s
}
