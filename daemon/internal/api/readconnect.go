package api

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const readConnectRule = "sensitive-read-then-connect"

// evidenceOfKind is f's first evidence item of kind, nil when it has none.
func evidenceOfKind(f model.Flag, kind string) *model.EvidenceItem {
	for i := range f.Evidence {
		if f.Evidence[i].Kind == kind {
			return &f.Evidence[i]
		}
	}
	return nil
}

// destinationOf is a connect item's org from the endpoint identity table,
// its host when the org is unknown, and the host.
func destinationOf(ev model.EvidenceItem) (dest, org, host string) {
	host, _ = splitHostPort(ev.Label)
	org = correlate.IdentifyCached(host).Org
	return firstNonEmpty([]string{org, host}), org, host
}

// readConnectWhy is the reason a sensitive-read-then-connect flag needs a
// look, from its evidence: whether the destination owns the file that was
// read and, when it does, why the connection still did not count as the
// credential in use. Empty for evidence recorded before readers were.
func readConnectWhy(f model.Flag) string {
	read, conn := evidenceOfKind(f, "read"), evidenceOfKind(f, "connect")
	if read == nil || conn == nil || read.PID == 0 {
		return ""
	}
	dest, org, _ := destinationOf(*conn)
	file := displayPath(read.Label, strings.TrimRight(explainHome(), "/"))
	switch {
	case len(read.Owners) == 0:
		return "No owner is on record for " + file + "; the connection went to " + dest + "."
	case org == "" || !slices.Contains(read.Owners, org):
		return dest + " does not own " + file + " (owner: " + strings.Join(read.Owners, ", ") + ")."
	case read.Sub == "agent tool read":
		return org + " owns " + file + ", but an agent tool read it into the model's context."
	default:
		return org + " owns " + file + ", but a process outside the reader's process tree made the connection."
	}
}

// patternDestinations counts the flags citing each destination (org, else
// host), busiest PatternListCap first.
func patternDestinations(flags []model.Flag) []model.PatternDestination {
	byDest := map[string]*model.PatternDestination{}
	for _, f := range flags {
		seen := map[string]bool{}
		for _, ev := range f.Evidence {
			if ev.Kind != "connect" {
				continue
			}
			dest, org, host := destinationOf(ev)
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
	return capList(out, model.PatternListCap)
}

// readerName names the process that read the file ("gh", "claude-code
// 2.1.281"); empty when the read item names no executable or the reader is
// the agent itself.
func readerName(r *model.EvidenceItem, agent string) string {
	if r == nil || r.Exe == "" {
		return ""
	}
	name := agents.HarnessLabel(r.Exe)
	if agent != "" && strings.HasPrefix(strings.ToLower(name), strings.ToLower(agent)) {
		return ""
	}
	return name
}

// patternReader is the reader readerName gives for most of the flags,
// empty when none names one.
func patternReader(flags []model.Flag) string {
	n := map[string]int{}
	for _, f := range flags {
		if name := readerName(evidenceOfKind(f, "read"), f.Agent); name != "" {
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
		s += fmt.Sprintf(" and %d more destination%s", more, plural(more))
	}
	return s
}
