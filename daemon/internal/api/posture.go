package api

import (
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// PostureItem is one thing the operator may need to act on.
type PostureItem struct {
	Kind      string `json:"kind"` // flag | incident | guard_pending | resource_pressure | coverage kinds
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  int    `json:"severity"` // 3 critical, 2 high, 1 medium, 0 info
	Detail    string `json:"detail,omitempty"`
	Timestamp string `json:"ts,omitempty"`
}

// Posture is the single headline answer: "do I need to look at this machine,
// and what is the one thing to look at first?" Every UI (console, menubar,
// fleet collector) renders from this instead of re-deriving it from raw lists.
//
// Invariant: every pending decision in Items appears in exactly one Group,
// and group item counts sum to NeedsYou (= len(Items)). CoverageItems are
// monitoring gaps and informational uninspected egress, counted separately;
// only a gap moves State off all-clear.
type Posture struct {
	State         string        `json:"state"` // all-clear | attention | critical
	NeedsYou      int           `json:"needs_you"`
	CoverageCount int           `json:"coverage_count"`
	Summary       string        `json:"summary"`
	Items         []PostureItem `json:"items"`
	CoverageItems []PostureItem `json:"coverage_items"`
	// Groups is the session-grouped attention queue every surface renders;
	// agent-less items sit in the "machine" group.
	Groups    []AttentionGroup `json:"groups,omitempty"`
	Generated string           `json:"generated"`
	Connected bool             `json:"connected"`
}

// handlePosture serves the operator headline. The computation lives in
// computePosture so the fleet heartbeat can ship the exact same headline the
// local UIs render — one derivation, three consumers (console, menubar,
// collector).
func (a *API) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.computePosture())
}

// CurrentPosture exposes the computed headline to non-HTTP consumers (the
// fleet heartbeat loop).
func (a *API) CurrentPosture() Posture { return a.computePosture() }

// PublishPostureIfChanged recomputes the headline and pushes a posture delta
// only when its state or counts changed: the drain loop calls this after
// flag/incident/guard changes, so dedupe happens here, not there.
func (a *API) PublishPostureIfChanged() { a.publishFreshPosture(false) }

// PublishPosture pushes the recomputed posture after a decision even at an
// unchanged count: the items differ, and counts also move without a publish
// (the 24 h window).
func (a *API) PublishPosture() { a.publishFreshPosture(true) }

func (a *API) publishFreshPosture(force bool) {
	if a.deltaHub == nil {
		return
	}
	a.lastPostureMu.Lock()
	a.postureGen++
	gen := a.postureGen
	a.lastPostureMu.Unlock()
	a.publishPosture(gen, a.computePosture(), force)
}

// publishPosture publishes p, computed as generation gen, unless a later
// computation was already published or (without force) nothing changed.
func (a *API) publishPosture(gen uint64, p Posture, force bool) {
	a.lastPostureMu.Lock()
	defer a.lastPostureMu.Unlock()
	if gen < a.lastPostureGen {
		return
	}
	if !force && p.State == a.lastPostureState && p.NeedsYou == a.lastPostureCount && p.CoverageCount == a.lastPostureCoverage {
		return
	}
	a.lastPostureGen = gen
	a.lastPostureState = p.State
	a.lastPostureCount = p.NeedsYou
	a.lastPostureCoverage = p.CoverageCount
	a.deltaHub.Publish(Delta{Type: "posture", Data: p})
}

// computePosture derives the operator headline from live status + stores.
// Deliberately derived, not persisted: posture is a view over state, never a
// second source of truth.
func (a *API) computePosture() Posture {
	since := time.Now().Add(-24 * time.Hour)
	patterns, patternErr := a.computePatternsResult(since, patternDefaultMin)
	failedReads := a.advisorReadFailures("flag")
	routine, routineErr := a.routineGroupsResult(since)
	failedReads = append(failedReads, a.advisorReadFailures("flag")...)
	if patternErr != nil || routineErr != nil {
		failedReads = append(failedReads, "flags")
	}
	return a.postureWithReadHealth(patterns, routine, failedReads)
}

// Preserve optional-enrichment faults in this calculation even if a later,
// narrower query reads only subjects whose advice is healthy.
func (a *API) advisorReadFailures(kind string) []string {
	if a.store == nil {
		return nil
	}
	return advisorReadFailuresFrom(a.store, kind)
}

// postureWith is computePosture over the 24 h patterns and routine groups
// the caller already computed.
func (a *API) postureWith(patterns []model.Pattern, routine []model.RoutineGroup) Posture {
	return a.postureWithReadHealth(patterns, routine, nil)
}

func (a *API) postureWithReadHealth(patterns []model.Pattern, routine []model.RoutineGroup, failedReads []string) Posture {
	return derivePosture(a.loadPostureInputs(a.statusFn(), patterns, routine, failedReads))
}
