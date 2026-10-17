package daemon

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// The coverage file is rewritten on every tagger tick while the daemon and a
// restart read it: a reader always sees one whole snapshot.
func TestCoverageFileIsNeverReadTorn(t *testing.T) {
	db := filepath.Join(t.TempDir(), "events.db")
	heartbeats := map[string]string{}
	for i := 0; i < 2000; i++ {
		heartbeats[fmt.Sprintf("collector-%04d", i)] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	reg := supervise.NewRegistry()
	reg.LoadLastProduced(heartbeats)
	persistLastProduced(db, reg)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				persistLastProduced(db, reg)
			}
		}
	}()
	torn := 0
	for i := 0; i < 2000; i++ {
		if got := loadLastProduced(db); len(got) != len(heartbeats) {
			torn++
		}
	}
	close(stop)
	wg.Wait()
	if torn > 0 {
		t.Fatalf("%d of 2000 reads saw a partial coverage file", torn)
	}
}
