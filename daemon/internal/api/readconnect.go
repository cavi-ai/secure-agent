package api

import (
	"slices"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/pattern"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/report"
)

const readConnectRule = posture.ReadConnectRule

// readConnectWhy is the reason a sensitive-read-then-connect flag needs a
// look, from its evidence: whether the destination owns the file that was
// read and, when it does, why the connection still did not count as the
// credential in use. Empty for evidence recorded before readers were.
func readConnectWhy(f model.Flag) string {
	read, conn := report.EvidenceOfKind(f, "read"), report.EvidenceOfKind(f, "connect")
	if read == nil || conn == nil || read.PID == 0 {
		return ""
	}
	dest, org, host := pattern.DestinationOf(*conn)
	file := report.DisplayPath(read.Label, strings.TrimRight(explainHome(), "/"))
	switch {
	case hostid.IdentifyCached(host).Class == "cloud":
		return "A connection was observed to " + dest + " infrastructure near the read of " + file + ". The receiving service and whether secret bytes were sent are not established."
	case len(read.Owners) == 0:
		return "No owner is on record for " + file + "; the connection went to " + dest + "."
	case org == "" || !slices.Contains(read.Owners, org):
		return "A connection to " + dest + " was observed near the read of " + file + "; configured credential destinations: " + strings.Join(read.Owners, ", ") + ". Secret transmission is not established."
	case read.Sub == "agent tool read":
		return org + " owns " + file + ", but an agent tool read it into the model's context."
	default:
		return org + " owns " + file + ", but a different process made the observed connection. The recorded evidence does not establish credential use."
	}
}
