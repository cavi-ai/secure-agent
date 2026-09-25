package daemon

import (
	"encoding/json"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

const (
	// planCacheName is the scan_cache row that carries the plan headroom
	// snapshots (collect.Plans) to the next run.
	planCacheName = "costs.plans"
	// planRestoreMaxAge bounds the snapshots a restart restores: a week, the
	// longest window a plan reports, after which every window has reset.
	planRestoreMaxAge = 7 * 24 * time.Hour
)

// planSaver saves collect.Plans() in the store when they changed.
type planSaver struct {
	st    *store.Store
	saved uint64 // collect.PlansVersion() at the last save
}

// restorePlans records the previous run's snapshots seen within
// planRestoreMaxAge of now, so /costs/plans answers from them until a newer
// token_count line replaces them, and returns the saver for this run.
func restorePlans(st *store.Store, now time.Time) *planSaver {
	if body, _, ok := st.ScanCache(planCacheName); ok {
		var saved []collect.PlanSnapshot
		if err := json.Unmarshal(body, &saved); err != nil {
			log.Printf("plans: restore: %v", err)
		}
		for _, p := range saved {
			if p.HomePath != "" && now.Sub(p.SeenAt) < planRestoreMaxAge {
				collect.RecordPlan(p.HomePath, p)
			}
		}
	}
	return &planSaver{st: st, saved: collect.PlansVersion()}
}

// save stores the snapshots when RecordPlan kept one since the last save.
// Not safe for concurrent use: the resource loop calls it.
func (p *planSaver) save() {
	v := collect.PlansVersion()
	if v == p.saved {
		return
	}
	body, err := json.Marshal(collect.Plans())
	if err != nil {
		log.Printf("plans: save: %v", err)
		return
	}
	p.st.PutScanCache(planCacheName, body, time.Now())
	p.saved = v
}
