package api

import (
	"net/http"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Snapshot is the console hot path in one payload: everything that must
// refresh when a bus event lands. Slow panels (fleet, audit, sources,
// rollup, uninspected, notify rules) stay on their own 30s cadence.
type Snapshot struct {
	Status  Status           `json:"status"`
	Flags   []model.Flag     `json:"flags"`
	Reviews store.ReviewPage `json:"reviews"`
	// Patterns are the repeating findings of the same 24h (at least 3 flags
	// each); the console renders them instead of the flags they cover.
	Patterns []model.Pattern `json:"patterns"`
	// Routine are the same reads across agents (at least 3 flags spanning
	// agents or files); the console renders one decision for each.
	Routine     []model.RoutineGroup   `json:"routine"`
	Incidents   []store.IncidentDetail `json:"incidents"`
	Events      []event.Event          `json:"events"`
	Posture     Posture                `json:"posture"`
	Suggestions []Suggestion           `json:"suggestions"`
	Mutes       []MutePair             `json:"mutes"`
	// Sessions is the durable session spine (live and recently ended) — the
	// Sessions tab renders from this, not from process-tree guesswork.
	Sessions []model.Session `json:"sessions"`
}

// snapshotReads is the store-derived part of a snapshot, read at one store
// write generation.
type snapshotReads struct {
	sessions []model.Session
	// events are unclassed: the price class reads the operator's price table.
	events    []event.Event
	incidents []store.IncidentDetail
	// flags carry finding review ids and titles; explanations read live
	// status and are added per request.
	flags         []model.Flag
	reviewLinkErr error
	reviews       store.ReviewPage
	// egress is the correlator summary the suggestions were read for.
	egress      []correlate.UninspectedSummary
	suggestions []Suggestion
	hostReadErr error
	// failedReads are the read failures met before the pattern reads.
	failedReads []string
	evidence    posture.Inputs
}

func (r snapshotReads) healthy() bool {
	return len(r.failedReads) == 0 && !r.reviews.Degraded && r.hostReadErr == nil && len(r.evidence.FailedReads) == 0
}

func (a *API) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := a.currentSnapshot()
	if err != nil {
		http.Error(w, "snapshot data unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, snapshot)
}

// currentSnapshot serves the store reads cached for the current write
// generation, or reads them; only reads without a failure are cached.
// Patterns and routine groups are computed on every request, between the two
// read groups as before, so each advisor health check follows its read.
func (a *API) currentSnapshot() (Snapshot, error) {
	now := a.clock()
	gen := a.store.WriteGeneration()
	reads, cached := a.flagReads.snapshot.get(gen, now)
	if !cached {
		var err error
		if reads, err = a.readSnapshotRecords(now); err != nil {
			return Snapshot{}, err
		}
	}
	flags := a.readPostureFlags(now)
	if flags.patternErr != nil {
		return Snapshot{}, flags.patternErr
	}
	if flags.routineErr != nil {
		return Snapshot{}, flags.routineErr
	}
	if !cached {
		a.readSnapshotRest(&reads, now)
		if reads.healthy() {
			a.flagReads.snapshot.put(gen, now, reads)
			a.flagReads.posture.put(gen, now, reads.evidence)
		}
	}
	return a.snapshotFrom(now, reads, flags), nil
}

func (a *API) incidentListResult(limit int) ([]store.IncidentDetail, error) {
	incidents, err := readIncidentList(a.store, limit)
	if err != nil {
		return nil, err
	}
	for i := range incidents {
		incidents[i].IncidentReport, err = currentIncidentReport(a.store, incidents[i].IncidentReport)
		if err != nil {
			return nil, err
		}
	}
	return incidents, nil
}

// readSnapshotRecords performs the snapshot's store reads that precede the
// pattern reads. Each advisor health check follows the read it reports on.
func (a *API) readSnapshotRecords(now time.Time) (snapshotReads, error) {
	var r snapshotReads
	var err error
	if r.sessions, r.events, err = readSnapshotRows(a.store); err != nil {
		return r, err
	}
	if r.incidents, err = a.incidentListResult(10); err != nil {
		return r, err
	}
	r.failedReads = a.advisorReadFailures("incident")
	r.flags, err = a.store.QueryFlags(store.FlagFilter{
		Unacted: true,
		Since:   now.Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		Limit:   200,
	})
	if err != nil {
		return r, err
	}
	r.failedReads = append(r.failedReads, a.advisorReadFailures("flag")...)
	r.reviewLinkErr = stampFindingReviewIDs(a.store, r.flags)
	if r.reviewLinkErr != nil {
		r.failedReads = append(r.failedReads, "finding reviews")
	}
	for i := range r.flags {
		r.flags[i].Title = posture.HumanFlagTitle(r.flags[i].Rule)
	}
	return r, nil
}

// readSnapshotRest performs the snapshot's store reads that follow the
// pattern reads.
func (a *API) readSnapshotRest(r *snapshotReads, now time.Time) {
	reviews, reviewErr := a.store.ListFindingReviews("", 100)
	if reviewErr != nil || r.reviewLinkErr != nil {
		reviews.Degraded = true
	}
	r.reviews = reviews
	egress := a.uninspectedEgress()
	r.egress = slices.Clone(egress)
	r.suggestions, r.hostReadErr = a.suggestionsFor(egress)
	r.evidence = a.readPostureEvidence(now)
}

// snapshotFrom completes cached reads with the inputs read on every request:
// live status, flag explanations, price classes, mutes, patterns, routine
// groups and posture's live inputs. Suggestions are read again when the
// correlator summary changed.
func (a *API) snapshotFrom(now time.Time, r snapshotReads, pf postureFlags) Snapshot {
	flags := slices.Clone(r.flags)
	a.stampExplains(flags)
	suggestions, hostReadErr := r.suggestions, r.hostReadErr
	if egress := a.uninspectedEgress(); !reflect.DeepEqual(egress, r.egress) {
		suggestions, hostReadErr = a.suggestionsFor(egress)
	}
	failedReads := append(slices.Clone(r.failedReads), pf.failedReads...)
	if hostReadErr != nil {
		failedReads = append(failedReads, "host advisor verdicts")
	}
	reviews := r.reviews
	reviews.Reviews = slices.Clone(reviews.Reviews)
	return Snapshot{
		Status:      a.currentStatus(),
		Flags:       flags,
		Reviews:     reviews,
		Patterns:    pf.patterns,
		Routine:     pf.routine,
		Incidents:   slices.Clone(r.incidents),
		Events:      priceClassed(slices.Clone(r.events)),
		Posture:     a.postureFrom(now, pf, failedReads, r.evidence),
		Suggestions: slices.Clone(suggestions),
		Mutes:       a.mutePairs(),
		Sessions:    slices.Clone(r.sessions),
	}
}

func (a *API) mutePairs() []MutePair {
	if a.mutes == nil {
		return []MutePair{}
	}
	return mutePairsFrom(a.mutes.Load())
}

func mutePairsFrom(policy map[string][]correlate.Mute) []MutePair {
	out := []MutePair{}
	for rule, mutes := range policy {
		for _, m := range mutes {
			out = append(out, MutePair{Rule: rule, Host: m.Host, Agent: m.Agent, Title: posture.HumanFlagTitle(rule)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

func (a *API) suggestionListResult() ([]Suggestion, error) {
	return a.suggestionsFor(a.uninspectedEgress())
}

// uninspectedEgress is the correlator's live summary; nil without one.
func (a *API) uninspectedEgress() []correlate.UninspectedSummary {
	if a.correlator == nil {
		return nil
	}
	return a.correlator.UninspectedEgressSummary()
}

func (a *API) suggestionsFor(egress []correlate.UninspectedSummary) ([]Suggestion, error) {
	if a.correlator == nil {
		return []Suggestion{}, nil
	}
	return readEgressSuggestions(a.store, egress)
}
