package doctor

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Store is the stored evidence the checks read.
type Store interface {
	SessionIdentityStats(time.Time) (int, int, int, int)
	DoctorWorkspaceRepos(time.Time) ([][2]string, error)
	SessionsCreatedSince(time.Time) int
	SessionsByHarness(time.Time) map[string]int
	TraceRowsWrittenByHarness() map[string]int
	ToolCallStats(time.Time) (int, int)
	PricingStats() (int, int, int, int)
	RetentionReport() []store.KindRetention
}

// GatherStoreFacts concentrates the stored evidence used by all Doctor
// probes. A narrower reader can supply these facts without an API instance.
func GatherStoreFacts(f *Facts, st Store) {
	f.sessionsTotal, f.sessionsNamed, f.sessionsWithWorkspace, f.sessionsWRepo = st.SessionIdentityStats(f.Boot)
	gitWorkspaces := map[string]bool{}
	workspaceRows, err := st.DoctorWorkspaceRepos(f.Boot)
	f.repoQueryError = err != nil
	for _, row := range workspaceRows {
		eligible, ok := gitWorkspaces[row[0]]
		if !ok {
			eligible = session.IsGitWorkspace(row[0])
			gitWorkspaces[row[0]] = eligible
		}
		if eligible {
			f.sessionsWithGitWorkspace++
			if row[1] != "" {
				f.sessionsGitWRepo++
			}
		}
	}
	f.sessionsLastHour = st.SessionsCreatedSince(f.Now.Add(-time.Hour))
	f.sessionsByHarness = st.SessionsByHarness(f.Boot)
	f.traceByHarness = st.TraceRowsWrittenByHarness()
	f.dupePairs, f.idless = st.ToolCallStats(f.Boot)
	f.claudePriced, f.claudeUnpriced, f.allUnpriced, f.allCalls = st.PricingStats()
	f.retention = st.RetentionReport()
}
