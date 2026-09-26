package api

import (
	"fmt"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// agentGroupFacts gathers, for an agent-level attention group, the
// processes and sessions behind its findings, so the group can say what it
// holds instead of that it could not be attributed.
type agentGroupFacts struct {
	pids          map[int32]bool
	extraPIDs     int // pattern pids beyond the served busiest list
	sessions      map[string]bool
	extraSessions int
	labels        []string
	seenLabel     map[string]bool
}

func newAgentGroupFacts() *agentGroupFacts {
	return &agentGroupFacts{pids: map[int32]bool{}, sessions: map[string]bool{}, seenLabel: map[string]bool{}}
}

func (g *agentGroupFacts) label(name, launcher string) {
	if l := processLabel(name, launcher); l != "" && !g.seenLabel[l] {
		g.seenLabel[l] = true
		g.labels = append(g.labels, l)
	}
}

func (g *agentGroupFacts) addFlag(f model.Flag) {
	if f.PID > 0 {
		g.pids[f.PID] = true
	}
	if f.SessionID != "" {
		g.sessions[f.SessionID] = true
	}
	if f.Process != nil {
		g.label(f.Process.Name, f.Process.Launcher)
	}
}

func (g *agentGroupFacts) addPattern(p model.Pattern) {
	for _, pid := range p.PIDs {
		g.pids[pid] = true
	}
	g.extraPIDs += max(0, p.PIDCount-len(p.PIDs))
	for _, s := range p.Sessions {
		g.sessions[s] = true
	}
	g.extraSessions += max(0, p.SessionCount-len(p.Sessions))
	for _, pp := range p.Processes {
		g.label(pp.Name, pp.Launcher)
	}
}

// summary: "3 processes (claude-code 2.1.281 via Claude.app) across 3
// sessions, all exited". "" when no finding named a process.
func (g *agentGroupFacts) summary(live map[int32]bool) string {
	n := len(g.pids) + g.extraPIDs
	if n == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d process%s", n, pluralES(n))
	if len(g.labels) > 0 {
		shown := g.labels
		if len(shown) > 3 {
			shown = shown[:3]
		}
		b.WriteString(" (" + strings.Join(shown, ", "))
		if len(g.labels) > len(shown) {
			fmt.Fprintf(&b, ", +%d more", len(g.labels)-len(shown))
		}
		b.WriteString(")")
	}
	switch s := len(g.sessions) + g.extraSessions; s {
	case 0:
		b.WriteString(", no session")
	case 1:
		b.WriteString(" in 1 session")
	default:
		fmt.Fprintf(&b, " across %d sessions", s)
	}
	running := 0
	for pid := range g.pids {
		if live[pid] {
			running++
		}
	}
	switch {
	case running == 0 && g.extraPIDs == 0 && n == 1:
		b.WriteString(", exited")
	case running == 0 && g.extraPIDs == 0:
		b.WriteString(", all exited")
	case running > 0:
		fmt.Fprintf(&b, ", %d still running", running)
	}
	return b.String()
}

// processLabel reads a process snapshot as "<harness> via <app>":
// "claude" launched as "Claude.app › claude-code 2.1.281" reads
// "claude-code 2.1.281 via Claude.app"; a child process keeps its own name
// ("bash in claude-code 2.1.281 via Claude.app").
func processLabel(name, launcher string) string {
	var bundle, harness string
	for _, part := range strings.Split(launcher, " › ") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
		case strings.HasSuffix(part, ".app"):
			if bundle == "" {
				bundle = part
			}
		default:
			harness = part
		}
	}
	label := name
	switch {
	case harness == "":
	case name == "" || strings.HasPrefix(harness, name):
		label = harness
	default:
		label = name + " in " + harness
	}
	if bundle != "" && label != "" {
		label += " via " + bundle
	}
	return label
}

func pluralES(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}
