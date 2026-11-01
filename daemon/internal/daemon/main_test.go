package daemon

import (
	"context"
	"os"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
)

// TestMain keeps the collectors a test daemon starts off the developer's own
// harness data: with these unset they resolve under each test's HOME. It also
// answers every reverse-DNS lookup with no names, so endpoint classification
// does not depend on the machine's resolver; that is set before any test runs
// because a test daemon classifies on its own goroutines.
func TestMain(m *testing.M) {
	for _, key := range []string{"CODEX_HOME", "HERMES_HOME", "HERMES_STATE_DIR", "OPENCLAW_HOME", "OPENCLAW_STATE_DIR"} {
		os.Unsetenv(key)
	}
	hostid.SetLookupAddrForTest(func(context.Context, string) ([]string, error) { return nil, nil })
	os.Exit(m.Run())
}
