package api

import (
	"context"
	"os"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
)

// TestMain answers every reverse-DNS lookup with no names, so endpoint
// identity and infra classification come from the CIDR and suffix tables
// alone, whatever the machine's resolver says. It is set once, before any test
// runs, because handlers classify on their own goroutines; it is never
// restored, as the process exits after m.Run.
func TestMain(m *testing.M) {
	hostid.SetLookupAddrForTest(func(context.Context, string) ([]string, error) { return nil, nil })
	os.Exit(m.Run())
}
