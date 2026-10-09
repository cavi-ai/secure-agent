package api

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// routineMin is the fewest open flags a routine group holds.
const routineMin = 3

// routineGroupKey is the attention group that holds the routine items.
const routineGroupKey = "routine"

// routineArea keys a read path: the home dot-directory it sits under
// (~/.docker), else the file itself.
func routineArea(path, home string) string {
	if home != "" && strings.HasPrefix(path, home+"/.") {
		if dir, _, found := strings.Cut(path[len(home)+1:], "/"); found {
			return home + "/" + dir
		}
	}
	return path
}

// readerOf is the reader label an expectation keys a read by; empty when
// the read recorded no process.
func readerOf(read model.EvidenceItem) string {
	tool := read.Sub == "agent tool read"
	if read.Exe == "" && !tool {
		return ""
	}
	return correlate.ReaderLabel(read.Exe, tool)
}

// routineExpectable reports whether every read f cites is reader on area,
// so marking its pairs expected resolves it and expects nothing the group
// does not name. A flag that also cites another reader or file, or reads
// with no recorded reader, stays for its own review.
func routineExpectable(f model.Flag, reader, area, home string) bool {
	if reader == "" {
		return false
	}
	reads := 0
	for _, ev := range f.Evidence {
		if ev.Kind != "read" {
			continue
		}
		reads++
		if readerOf(ev) != reader || routineArea(ev.Label, home) != area {
			return false
		}
	}
	return reads > 0 && len(expectedPairs(f)) > 0
}

// routineGroups groups the open read-then-connect flags raised since since
// by reader and area, whichever agent raised them. A group is kept when it
// holds routineMin flags and spans agents or files; most flags first.
func (a *API) routineGroups(since time.Time) []model.RoutineGroup {
	if a.store == nil {
		return []model.RoutineGroup{}
	}
	flags := a.store.QueryFlags(store.FlagFilter{Rule: readConnectRule, Unacted: true, Since: since.UTC().Format(time.RFC3339), Limit: patternFlagLimit})
	sort.SliceStable(flags, func(i, j int) bool { return flags[i].TS.After(flags[j].TS) })
	home := strings.TrimRight(explainHome(), "/")
	type group struct {
		reader, area string
		flags        []model.Flag
		files        map[string]bool
		agents       map[string]int
	}
	byKey := map[string]*group{}
	var keys []string
	for _, f := range flags {
		read := evidenceOfKind(f, "read")
		if read == nil || !filepath.IsAbs(read.Label) {
			continue
		}
		reader, area := readerOf(*read), routineArea(read.Label, home)
		key := "routine|" + reader + "|" + area
		g := byKey[key]
		if g == nil {
			g = &group{reader: reader, area: area, files: map[string]bool{}, agents: map[string]int{}}
			byKey[key] = g
			keys = append(keys, key)
		}
		g.flags = append(g.flags, f)
		g.files[read.Label] = true
		g.agents[f.Agent]++
	}
	out := []model.RoutineGroup{}
	for _, key := range keys {
		g := byKey[key]
		if len(g.flags) < routineMin || (len(g.agents) < 2 && len(g.files) < 2) {
			continue
		}
		out = append(out, routineGroup(key, g.reader, g.area, g.flags, g.files, g.agents, home))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// routineDestinations names the busiest two destinations (org, else host):
// "GitHub", "Google and Cloudflare", "GitHub, Google and 4 more".
func routineDestinations(dests []model.PatternDestination, total int) string {
	var names []string
	for _, d := range dests {
		if len(names) == 2 {
			break
		}
		names = append(names, firstNonEmpty([]string{d.Org, d.Host}))
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

func routineGroup(key, reader, area string, flags []model.Flag, files map[string]bool, agentCounts map[string]int, home string) model.RoutineGroup {
	rg := model.RoutineGroup{Key: key, Reader: reader, Files: len(files), Count: len(flags)}
	rg.Area = displayPath(area, home)
	if len(files) == 1 {
		for f := range files {
			rg.Area = displayPath(f, home)
		}
	}
	for agent := range agentCounts {
		rg.Agents = append(rg.Agents, agent)
	}
	sort.Slice(rg.Agents, func(i, j int) bool {
		if x, y := agentCounts[rg.Agents[i]], agentCounts[rg.Agents[j]]; x != y {
			return x > y
		}
		return rg.Agents[i] < rg.Agents[j]
	})
	dests := map[string]bool{}
	worst := model.Disposition{}
	var ids, expectable []string
	for _, f := range flags {
		for _, ev := range f.Evidence {
			if ev.Kind == "connect" {
				if dest, _, host := destinationOf(ev); host != "" {
					dests[dest] = true
				}
			}
		}
		if d := dispositionFor(f); worst.State == "" || dispositionRank(d.State) > dispositionRank(worst.State) {
			worst = d
		}
		if len(ids) < model.PatternFlagIDCap {
			ids = append(ids, f.ID)
		}
		if routineExpectable(f, reader, area, home) && len(expectable) < model.PatternFlagIDCap {
			expectable = append(expectable, f.ID)
		}
	}
	rg.Destinations = patternDestinations(flags)
	rg.DestinationCount = len(dests)
	rg.Disposition = worst
	rg.Assessment = assessmentForFlags(flags)
	rg.Expectable = len(expectable)
	rg.FlagIDs = ids

	who := firstNonEmpty([]string{reader, "A process with no recorded name"})
	what := "read " + rg.Area
	if len(files) > 1 {
		what = fmt.Sprintf("read %d files in %s", len(files), rg.Area)
	}
	rg.Summary = fmt.Sprintf("%s %s, then connected to %s — %d time%s across %d agent%s.",
		who, what, routineDestinations(rg.Destinations, rg.DestinationCount), rg.Count, plural(rg.Count), len(rg.Agents), plural(len(rg.Agents)))

	if len(expectable) > 0 {
		consequence := fmt.Sprintf("Each exact reader, file and destination these %d flags cite is marked expected for its agent, and the flags are marked reviewed. A new reader, file or destination still flags. Forget them under Policy.", len(expectable))
		switch rest := rg.Count - len(expectable); {
		case rest == 1:
			consequence += " 1 flag that cites another reader or file stays open for its own review."
		case rest > 1:
			consequence += fmt.Sprintf(" %d flags that cite another reader or file stay open for their own review.", rest)
		}
		rg.Actions = append(rg.Actions, model.ExplainAction{
			ID: "expect-all", Label: "Treat as routine", Consequence: consequence,
			Method: http.MethodPost, Path: "/expected", Body: map[string]any{"flag_ids": expectable},
		})
	}
	rg.Actions = append(rg.Actions, model.ExplainAction{
		ID: "dismiss-all", Label: fmt.Sprintf("Dismiss all %d", len(ids)),
		Consequence: "Every flag here is marked reviewed; the rules keep watching for the next one.",
		Method:      http.MethodPost, Path: "/flags/acknowledge", Body: map[string]any{"flag_ids": ids},
	})
	return rg
}
