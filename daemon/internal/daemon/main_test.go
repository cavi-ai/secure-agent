package daemon

import (
	"os"
	"testing"
)

// TestMain keeps the collectors a test daemon starts off the developer's own
// harness data: with these unset they resolve under each test's HOME.
func TestMain(m *testing.M) {
	for _, key := range []string{"CODEX_HOME", "HERMES_HOME", "HERMES_STATE_DIR", "OPENCLAW_HOME", "OPENCLAW_STATE_DIR"} {
		os.Unsetenv(key)
	}
	os.Exit(m.Run())
}
