package api

import (
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

// PostureItem is one thing the operator may need to act on.
type PostureItem = posture.PostureItem

type AttentionItem = posture.AttentionItem

type AttentionGroup = posture.AttentionGroup

type AttentionSummary = posture.AttentionSummary

type AttentionBucket = posture.AttentionBucket

type AttentionReference = posture.AttentionReference

// AttentionBuckets and PostureItemAttentionKinds are the summary enumerations
// the console and menu bar copy; posture defines them.
var (
	AttentionBuckets          = posture.AttentionBuckets
	PostureItemAttentionKinds = posture.PostureItemAttentionKinds
)

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
// second source of truth. Store reads are cached for the current write
// generation when none failed.
func (a *API) computePosture() Posture {
	now := a.clock()
	gen := a.store.WriteGeneration()
	flags := a.readPostureFlags(now)
	failedReads := slices.Clone(flags.failedReads)
	if flags.patternErr != nil || flags.routineErr != nil {
		failedReads = append(failedReads, "flags")
	}
	return a.postureFrom(now, flags, failedReads, a.postureEvidenceAt(gen, now))
}

// postureEvidenceAt serves the posture evidence cached for gen or reads it;
// evidence that met a read failure is not cached.
func (a *API) postureEvidenceAt(gen uint64, now time.Time) posture.Inputs {
	if ev, ok := a.flagReads.posture.get(gen, now); ok {
		return ev
	}
	ev := a.readPostureEvidence(now)
	if len(ev.FailedReads) == 0 {
		a.flagReads.posture.put(gen, now, ev)
	}
	return ev
}

// postureFlags are the 24 h patterns and routine groups with the advisor read
// failures their flag reads left. They also read live status, the allowlist,
// expectations, the host identity cache and the clock, so every request
// computes them; their flag rows come from flagReads.
type postureFlags struct {
	patterns    []model.Pattern
	routine     []model.RoutineGroup
	patternErr  error
	routineErr  error
	failedReads []string
}

// readPostureFlags computes the 24 h patterns and routine groups at now.
func (a *API) readPostureFlags(now time.Time) postureFlags {
	since := dayWindow(now)
	var r postureFlags
	r.patterns, r.patternErr = a.computePatternsResult(since, patternDefaultMin)
	r.failedReads = a.advisorReadFailures("flag")
	r.routine, r.routineErr = a.routineGroupsResult(since)
	r.failedReads = append(r.failedReads, a.advisorReadFailures("flag")...)
	return r
}

// Preserve optional-enrichment faults in this calculation even if a later,
// narrower query reads only subjects whose advice is healthy.
func (a *API) advisorReadFailures(kind string) []string {
	if a.store == nil {
		return nil
	}
	return advisorReadFailuresFrom(a.store, kind)
}

// postureFrom derives posture from flags and evidence with live status,
// resource controls and pending prompts read now; ev stays unchanged.
func (a *API) postureFrom(now time.Time, flags postureFlags, failedReads []string, ev posture.Inputs) Posture {
	return a.postureFromStatus(a.statusFn(), now, flags, failedReads, ev)
}

func (a *API) postureFromStatus(status Status, now time.Time, flags postureFlags, failedReads []string, ev posture.Inputs) Posture {
	return derivePosture(a.postureInputsFrom(status, now, flags.patterns, flags.routine, failedReads, ev))
}

// derivePosture is posture.Derive with dispositionFor supplying flag verdicts.
func derivePosture(in posture.Inputs) Posture { return Posture(posture.Derive(in, dispositionFor)) }
