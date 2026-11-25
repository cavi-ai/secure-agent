package api

import (
	"net/http"
	"reflect"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

// PostureItem is one thing the operator may need to act on.
type PostureItem = posture.PostureItem

// Posture is a defined type so the /posture response keeps the wire name api.Posture.
type Posture posture.Posture

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
	if !force && p.State == a.lastPostureState && p.NeedsYou == a.lastPostureCount && p.CoverageCount == a.lastPostureCoverage && reflect.DeepEqual(p.AttentionSummary, a.lastPostureAttention) && reflect.DeepEqual(p.CoverageItems, a.lastPostureEvidence) {
		return
	}
	a.lastPostureGen = gen
	a.lastPostureState = p.State
	a.lastPostureCount = p.NeedsYou
	a.lastPostureCoverage = p.CoverageCount
	a.lastPostureEvidence = p.CoverageItems
	a.lastPostureAttention = p.AttentionSummary
	a.deltaHub.Publish(Delta{Type: "posture", Data: p})
}

// computePosture derives the operator headline from live status + stores.
// Deliberately derived, not persisted: posture is a view over state, never a
// second source of truth.
func (a *API) computePosture() Posture {
	since := dayWindow(time.Now())
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

// postureWithReadHealth is computePosture over the 24 h patterns and routine
// groups the caller already computed.
func (a *API) postureWithReadHealth(patterns []model.Pattern, routine []model.RoutineGroup, failedReads []string) Posture {
	return derivePosture(a.loadPostureInputs(a.statusFn(), patterns, routine, failedReads))
}
