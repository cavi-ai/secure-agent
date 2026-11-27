package main

// The collector store: an in-memory per-node rollup over a persistence seam.
// The seam (envelopeLog) is deliberately tiny — append and query — so a
// SQLite backend can replace the JSONL reference implementation without
// touching rollup semantics. 0600 files in a 0700 directory — the collector
// sees fleet security data and must not be the weak link.

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// countWindow is the rolling horizon behind the "24h" counts. Lifetime
// counters only grow — an operator can't tell "quiet day" from "alert
// storm" from them, so every headline number is windowed instead.
const countWindow = 24 * time.Hour

// NodeState is everything the rollup needs about one node. Fields are
// additive over the original reference shape; windowed counts are computed
// at snapshot time so they decay even when a node goes quiet.
type NodeState struct {
	NodeID  string `json:"node_id"`
	Version string `json:"version"`
	// Hostname/Labels arrive in status envelopes; empty on legacy nodes that
	// only push events.
	Hostname string            `json:"hostname,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	// LastSeen is liveness (any accepted envelope — heartbeats included).
	// LastEvent is the most recent flag/incident/guard — security activity.
	LastSeen  time.Time `json:"last_seen"`
	LastEvent time.Time `json:"last_event,omitempty"`
	// Lifetime counters (kept for continuity; the UI leads with windowed).
	Flags          int `json:"flags"`
	Incidents      int `json:"incidents"`
	GuardDecisions int `json:"guard_decisions"`
	GuardAllows    int `json:"guard_allows"`
	GuardDenies    int `json:"guard_denies"`
	// Rolling 24h windows, recomputed on every snapshot.
	Flags24h         int `json:"flags_24h"`
	CriticalFlags24h int `json:"critical_flags_24h"`
	Incidents24h     int `json:"incidents_24h"`
	// Posture mirrors the node's own /posture headline (status envelopes).
	PostureState   string `json:"posture_state,omitempty"`
	PostureSummary string `json:"posture_summary,omitempty"`
	NeedsYou       int    `json:"needs_you,omitempty"`
	Agents         int    `json:"agents,omitempty"`
	// HasStatus distinguishes heartbeat-capable nodes (tight liveness
	// thresholds) from legacy event-only nodes (lenient ones).
	HasStatus      bool   `json:"has_status"`
	LatestIncident string `json:"latest_incident,omitempty"`
	LatestFlag     string `json:"latest_flag,omitempty"`
	// Gaps counts deliveries the node stamped but that never arrived —
	// backlog-cap drops, collector downtime, restarts mid-flight. Delivery is
	// best-effort by design; gaps make the loss honest instead of silent.
	Gaps int `json:"gaps"`
	// Budget is the node's resource-budget posture from its latest heartbeat
	// (nil on legacy nodes). Lets the cross-node view rank by budget pressure.
	Budget *BudgetState `json:"budget,omitempty"`
	BootID string       `json:"boot_id,omitempty"`
}

// gapGrace is how long a missing sequence number is tolerated before it
// counts as lost — retries finish within ~20s, so 90s is well clear of
// reordering and retry noise.
const gapGrace = 90 * time.Second

// maxTrackedHoles bounds the per-node open-hole set; overflow is counted as
// confirmed loss (a hole that old is never coming back).
const maxTrackedHoles = 2048

// Keep a bounded history of applied deliveries. One minute covers the
// publisher's four 10-second HTTP attempts and 7.5 seconds of retry backoff.
const (
	redeliveryWindow    = time.Minute
	maxRecentDeliveries = 1024
)

// maxNodeSessions is the most session records one node keeps, in memory and
// in its checkpoint. The node's last-trace map holds at most as many entries.
const maxNodeSessions = 512

type deliveryKey [sha256.Size]byte

type appliedDelivery struct {
	Key deliveryKey
	At  time.Time
}

// windowEvent is one security event inside the rolling count window.
type windowEvent struct {
	TS       time.Time
	Kind     string // flag | incident
	Rule     string // flag rule id — the cross-node correlation key
	Severity int    // flag severity; incident risk mapped CRITICAL→3, HIGH→2, else 1
}

// nodeRuntime is the mutable per-node state: the rollup plus the window ring
// and the sequence-tracking state for gap detection.
type nodeRuntime struct {
	state  *NodeState
	recent []windowEvent
	// sessions is the latest record per session id seen from this node — the
	// cross-node view's per-node slice. At most maxNodeSessions records.
	sessions map[string]sessionPayload
	// lastTrace keeps the most recent trace per session so the cross-node
	// timeline can show "what is it doing now". At most maxNodeSessions
	// entries; an evicted session's trace goes with it.
	lastTrace map[string]tracePayload
	// Sequence tracking (per boot): maxSeq is the highest seq seen this boot;
	// holes are skipped sequence ranges and when each range opened, pending
	// either a late arrival (retry/reorder) or confirmation as a gap.
	maxSeq        uint64
	holes         []sequenceHole
	retiredBoots  []string
	confirmedGaps int
	// The FIFO bounds history, and the index gives each delivery's receipt time.
	applied   []appliedDelivery
	appliedAt map[deliveryKey]time.Time
}

type sequenceHole struct {
	First, Last uint64
	Opened      time.Time
}

// statusPayload mirrors model.NodeStatus on the node side; only the fields
// the rollup consumes are decoded.
type statusPayload struct {
	Hostname       string            `json:"hostname"`
	Agents         int               `json:"agents"`
	PostureState   string            `json:"posture_state"`
	PostureSummary string            `json:"posture_summary"`
	NeedsYou       int               `json:"needs_you"`
	Labels         map[string]string `json:"labels"`
	Budget         *BudgetState      `json:"budget,omitempty"`
}

// BudgetState is the per-node resource-budget posture from the heartbeat
// (mirrors model.BudgetStatus). Counts only, so a fleet view can rank nodes
// by budget pressure without fetching each node's resource detail.
type BudgetState struct {
	Mode       string `json:"mode"`
	Enforced   bool   `json:"enforced"`
	OverBudget int    `json:"over_budget"`
	Approval   int    `json:"approval"`
	Contained  int    `json:"contained"`
	Paused     int    `json:"paused"`
}

// sessionPayload mirrors model.Session on the node side. The collector keeps
// the latest record per (node, session id) — the cross-node "who is working
// where" view.
type sessionPayload struct {
	ID         string `json:"id"`
	Harness    string `json:"harness"`
	Workspace  string `json:"workspace"`
	Repo       string `json:"repo"`
	Branch     string `json:"branch"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	RootPID    int    `json:"root_pid"`
	StartedAt  string `json:"started_at"`
	EndedAt    string `json:"ended_at"`
	LastSeenAt string `json:"last_seen_at"`
}

// FleetSession is one session as the cross-node view shows it: the node it
// ran on plus its labels (so "env=prod" filters work across machines).
type FleetSession struct {
	NodeID   string            `json:"node_id"`
	Hostname string            `json:"hostname,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	sessionPayload
}

// tracePayload mirrors event.Event's trace fields on the node side — enough
// to render a cross-node timeline without pulling the raw OS event flood.
type tracePayload struct {
	Kind       int     `json:"kind"`
	TS         string  `json:"ts"`
	SessionID  string  `json:"session_id"`
	Tool       string  `json:"tool"`
	ToolStatus string  `json:"tool_status"`
	DurationMs int     `json:"duration_ms"`
	Model      string  `json:"model"`
	TokensIn   int     `json:"tokens_in"`
	TokensOut  int     `json:"tokens_out"`
	CostUSD    float64 `json:"cost_usd"`
}

// envelopeFile is the on-disk record: the envelope plus the receipt time, so
// delivery lag is distinguishable from event time.
type envelopeFile struct {
	ReceivedAt string   `json:"received_at"`
	Envelope   Envelope `json:"envelope"`
}

// envelopeLog is the persistence seam between the rollup and storage. The
// JSONL implementation below is the reference; a SQLite backend slots in by
// satisfying these methods.
type envelopeLog interface {
	Append(env Envelope, receivedAt string) error
	Query(nodeID string, kinds map[string]bool, limit int) []envelopeFile
}

// Store is the in-memory rollup over an envelopeLog.
type Store struct {
	mu    sync.Mutex
	log   envelopeLog
	nodes map[string]*nodeRuntime
}

func NewStore(dir string) (*Store, error) {
	return newStoreWithLog(newJSONLLog(dir, logMaxBytes, logKeepRotated))
}

func newStoreWithLog(l *jsonlLog) (*Store, error) {
	s := &Store{log: l, nodes: map[string]*nodeRuntime{}}
	if err := l.replay(s); err != nil {
		return nil, err
	}
	l.saveCheckpoint = s.saveCheckpoint
	return s, nil
}

// Append stores one verified envelope and folds it into the rollup. An
// identical sequenced envelope received recently is acknowledged without
// being stored or counted again.
func (s *Store) Append(env Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyOnce(env, time.Now().UTC().Format(time.RFC3339Nano), true)
}

// applyOnce shares the duplicate check across live delivery and replay.
// Caller must hold mu or be single-threaded. Replay supplies records that are
// already on disk, so only live delivery writes to the log.
func (s *Store) applyOnce(env Envelope, receivedAt string, persist bool) error {
	key, tracked := envelopeDeliveryKey(env)
	ts := receiptTime(receivedAt)
	cutoff := ts.Add(-redeliveryWindow)
	if tracked && s.nodes[env.NodeID].isRedelivery(key, cutoff) {
		return nil
	}
	if persist {
		if err := s.log.Append(env, receivedAt); err != nil {
			return err
		}
	}
	s.apply(env, receivedAt)
	if tracked {
		s.nodes[env.NodeID].rememberDelivery(key, ts, cutoff)
	}
	return nil
}

func receiptTime(receivedAt string) time.Time {
	ts, _ := time.Parse(time.RFC3339Nano, receivedAt)
	if ts.IsZero() {
		ts = time.Now()
	}
	return ts
}

func (s *Store) runtime(nodeID string) *nodeRuntime {
	rt := s.nodes[nodeID]
	if rt == nil {
		rt = &nodeRuntime{state: &NodeState{NodeID: nodeID}}
		s.nodes[nodeID] = rt
	}
	return rt
}

// Separate publisher sinks can share a boot ID and use independent sequence
// counters. Hash the full envelope using the log's JSON encoding so the same
// delivery has the same key after replay. Legacy envelopes are untracked.
func envelopeDeliveryKey(env Envelope) (deliveryKey, bool) {
	if env.Boot == "" || env.Seq == 0 {
		return deliveryKey{}, false
	}
	body, err := json.Marshal(env)
	if err != nil {
		return deliveryKey{}, false // Persistence handles invalid envelopes.
	}
	return sha256.Sum256(body), true
}

func (rt *nodeRuntime) isRedelivery(key deliveryKey, cutoff time.Time) bool {
	if rt == nil {
		return false
	}
	at, ok := rt.appliedAt[key]
	return ok && !at.Before(cutoff)
}

func (rt *nodeRuntime) rememberDelivery(key deliveryKey, ts, cutoff time.Time) {
	drop := 0
	for drop < len(rt.applied) && (rt.applied[drop].At.Before(cutoff) || len(rt.applied)-drop >= maxRecentDeliveries) {
		entry := rt.applied[drop]
		if rt.appliedAt[entry.Key] == entry.At {
			delete(rt.appliedAt, entry.Key)
		}
		drop++
	}
	rt.applied = rt.applied[drop:]
	if rt.appliedAt == nil {
		rt.appliedAt = make(map[deliveryKey]time.Time)
	}
	rt.appliedAt[key] = ts
	rt.applied = append(rt.applied, appliedDelivery{Key: key, At: ts})
}

// apply folds one envelope into the in-memory rollup. Caller must hold mu
// (the replay path is single-threaded).
func (s *Store) apply(env Envelope, receivedAt string) {
	rt := s.runtime(env.NodeID)
	st := rt.state
	ts := receiptTime(receivedAt)
	currentBoot := env.Boot == "" || rt.trackSeq(env.Boot, env.Seq, ts)
	// Delayed deliveries still carry useful evidence, but cannot reset the
	// active stream's sequence health or roll back its reported version.
	if currentBoot && env.Version != "" {
		st.Version = env.Version
	}
	if ts.After(st.LastSeen) {
		st.LastSeen = ts
	}
	switch env.Kind {
	case "flag":
		st.Flags++
		st.LatestFlag = summarize(env.Payload, "rule", 120)
		st.LastEvent = ts
		rt.recent = appendWindow(rt.recent, windowEvent{
			TS: ts, Kind: "flag",
			Rule:     summarize(env.Payload, "rule", 120),
			Severity: flagSeverity(env.Payload),
		}, ts)
	case "incident":
		st.Incidents++
		st.LatestIncident = summarize(env.Payload, "summary", 200)
		st.LastEvent = ts
		rt.recent = appendWindow(rt.recent, windowEvent{TS: ts, Kind: "incident", Severity: incidentSeverity(env.Payload)}, ts)
	case "guard":
		st.GuardDecisions++
		st.LastEvent = ts
		switch summarize(env.Payload, "verdict", 40) {
		case "allow":
			st.GuardAllows++
		case "deny":
			st.GuardDenies++
		}
	case "status":
		var p statusPayload
		if json.Unmarshal(env.Payload, &p) == nil {
			st.HasStatus = true
			st.Hostname = p.Hostname
			st.Labels = p.Labels
			st.Agents = p.Agents
			st.PostureState = p.PostureState
			st.PostureSummary = p.PostureSummary
			st.NeedsYou = p.NeedsYou
			st.Budget = p.Budget
		}
	case "session":
		var p sessionPayload
		if json.Unmarshal(env.Payload, &p) == nil && p.ID != "" {
			if rt.sessions == nil {
				rt.sessions = map[string]sessionPayload{}
			}
			rt.sessions[p.ID] = p
			rt.boundSessions(p.ID)
		}
	case "trace":
		var p tracePayload
		if json.Unmarshal(env.Payload, &p) == nil && p.SessionID != "" {
			if rt.lastTrace == nil {
				rt.lastTrace = map[string]tracePayload{}
			}
			// Last write wins; envelopes arrive near-chronologically and the
			// view only wants the latest state, so no timestamp comparison.
			rt.lastTrace[p.SessionID] = p
			rt.boundTraces()
		}
	}
}

// boundSessions evicts records past maxNodeSessions, ended before live and
// oldest LastSeenAt first, with their traces. keep is never evicted.
func (rt *nodeRuntime) boundSessions(keep string) {
	over := len(rt.sessions) - maxNodeSessions
	if over <= 0 {
		return
	}
	evictFirst(rt.sessions, over, func(id string) bool { return id != keep }, compareSessionEviction, func(id string) {
		delete(rt.sessions, id)
		delete(rt.lastTrace, id)
	})
}

// boundTraces evicts traces without a session record, oldest TS first, while
// the trace map holds more than maxNodeSessions entries.
func (rt *nodeRuntime) boundTraces() {
	over := len(rt.lastTrace) - maxNodeSessions
	if over <= 0 {
		return
	}
	orphan := func(id string) bool {
		_, ok := rt.sessions[id]
		return !ok
	}
	evictFirst(rt.lastTrace, over, orphan, compareTraceEviction, func(id string) { delete(rt.lastTrace, id) })
}

// compareSessionEviction orders ended before live, then older LastSeenAt first.
func compareSessionEviction(a, b sessionPayload) int {
	if aEnded, bEnded := a.Status == "ended", b.Status == "ended"; aEnded != bEnded {
		if aEnded {
			return -1
		}
		return 1
	}
	return compareEvictionTimestamps(a.LastSeenAt, b.LastSeenAt)
}

func compareTraceEviction(a, b tracePayload) int {
	return compareEvictionTimestamps(a.TS, b.TS)
}

func compareEvictionTimestamps(a, b string) int {
	// Missing or malformed timestamps rank as the zero time. The caller
	// breaks ties by ID.
	at, _ := time.Parse(time.RFC3339Nano, a)
	bt, _ := time.Parse(time.RFC3339Nano, b)
	return at.Compare(bt)
}

// evictFirst calls evict for the n candidate ids of m that order first, ties
// broken by id. One eviction costs a single scan; more cost one sort.
func evictFirst[V any](m map[string]V, n int, candidate func(string) bool, order func(a, b V) int, evict func(string)) {
	if n == 1 {
		var victim string
		var victimValue V
		found := false
		for id, v := range m {
			if candidate(id) && (!found || cmp.Or(order(v, victimValue), strings.Compare(id, victim)) < 0) {
				victim, victimValue, found = id, v, true
			}
		}
		if found {
			evict(victim)
		}
		return
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		if candidate(id) {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b string) int { return cmp.Or(order(m[a], m[b]), strings.Compare(a, b)) })
	for _, id := range ids[:min(n, len(ids))] {
		evict(id)
	}
}

// trackSeq folds one envelope's (boot, seq) into gap detection. A new boot
// resets the expectation (a restart is not loss); within a boot, skipped
// seqs open holes that late arrivals can still close — deliveries complete
// out of order (concurrent goroutines, retries), so holes only count as
// gaps after gapGrace has passed at snapshot time.
func (rt *nodeRuntime) trackSeq(boot string, seq uint64, ts time.Time) bool {
	if boot != rt.state.BootID {
		for _, retired := range rt.retiredBoots {
			if boot == retired {
				return false
			}
		}
		if rt.state.BootID != "" {
			rt.retiredBoots = append(rt.retiredBoots, rt.state.BootID)
			if len(rt.retiredBoots) > 64 {
				rt.retiredBoots = rt.retiredBoots[1:]
			}
		}
		rt.state.BootID = boot
		rt.maxSeq = seq // first contact with this boot is the sync point
		rt.holes = nil
		rt.confirmedGaps = 0
		return true
	}
	if seq > rt.maxSeq {
		if seq-rt.maxSeq > 1 {
			rt.holes = append(rt.holes, sequenceHole{First: rt.maxSeq + 1, Last: seq - 1, Opened: ts})
			rt.boundHoles()
		}
		rt.maxSeq = seq
		return true
	}
	for i, hole := range rt.holes {
		if seq < hole.First || seq > hole.Last {
			continue
		}
		switch {
		case hole.First == hole.Last:
			rt.holes = append(rt.holes[:i], rt.holes[i+1:]...)
		case seq == hole.First:
			rt.holes[i].First++
		case seq == hole.Last:
			rt.holes[i].Last--
		default:
			rt.holes[i].Last = seq - 1
			rt.holes = append(rt.holes, sequenceHole{First: seq + 1, Last: hole.Last, Opened: hole.Opened})
			rt.boundHoles()
		}
		break
	}
	return true
}

// Space is bounded by missing ranges, not the size of a sequence jump.
// Only pathological fragmentation retires a range as confirmed loss.
func (rt *nodeRuntime) boundHoles() {
	if len(rt.holes) <= maxTrackedHoles {
		return
	}
	oldest := 0
	for i, hole := range rt.holes {
		if hole.Opened.Before(rt.holes[oldest].Opened) {
			oldest = i
		}
	}
	hole := rt.holes[oldest]
	rt.confirmedGaps = addGapCount(rt.confirmedGaps, hole.Last-hole.First+1)
	rt.holes = append(rt.holes[:oldest], rt.holes[oldest+1:]...)
}

func addGapCount(n int, missing uint64) int {
	maxInt := int(^uint(0) >> 1)
	if missing > uint64(maxInt-n) {
		return maxInt
	}
	return n + int(missing)
}

// gapCount totals confirmed loss plus holes older than the grace period.
func (rt *nodeRuntime) gapCount(now time.Time) int {
	n := rt.confirmedGaps
	for _, hole := range rt.holes {
		if now.Sub(hole.Opened) > gapGrace {
			n = addGapCount(n, hole.Last-hole.First+1)
		}
	}
	return n
}

// appendWindow pushes one event into the ring and prunes entries older than
// the count window, keeping memory O(events-per-day) per node.
func appendWindow(ring []windowEvent, ev windowEvent, now time.Time) []windowEvent {
	ring = append(ring, ev)
	cutoff := now.Add(-countWindow)
	kept := ring[:0]
	for _, e := range ring {
		if e.TS.After(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

// windowCounts tallies the ring inside the window at snapshot time — counts
// decay as time passes even if no new envelope arrives.
func windowCounts(ring []windowEvent, now time.Time) (flags, criticalFlags, incidents int) {
	cutoff := now.Add(-countWindow)
	for _, e := range ring {
		if !e.TS.After(cutoff) {
			continue
		}
		switch e.Kind {
		case "flag":
			flags++
			if e.Severity >= 3 {
				criticalFlags++
			}
		case "incident":
			incidents++
		}
	}
	return
}

// RuleAggregate is one flag rule's fleet-wide footprint inside the rolling
// window — the "same thing firing on N/M nodes?" answer. One node with a
// read-then-connect is an incident; five nodes with it is a bad release.
type RuleAggregate struct {
	Rule        string   `json:"rule"`
	Nodes       int      `json:"nodes"`
	NodeIDs     []string `json:"node_ids,omitempty"`
	Flags24h    int      `json:"flags_24h"`
	Critical24h int      `json:"critical_24h"`
}

// FleetRules is the /fleet/rules response: aggregates plus the node total so
// "N of M nodes" needs no second call.
type FleetRules struct {
	TotalNodes int             `json:"total_nodes"`
	Rules      []RuleAggregate `json:"rules"`
}

// RuleAggregates groups in-window flag events by rule across all nodes.
// Flags only (not incidents): incidents derive 1:1 from flags, so counting
// both would double-count every finding. Sort: spread (nodes) beats volume —
// a rule firing on many nodes is a fleet problem; a rule firing many times
// on one node is a node problem.
func (s *Store) RuleAggregates() FleetRules {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-countWindow)
	type agg struct {
		nodes    map[string]bool
		flags    int
		critical int
	}
	byRule := map[string]*agg{}
	for nodeID, rt := range s.nodes {
		for _, e := range rt.recent {
			if e.Kind != "flag" || e.Rule == "" || !e.TS.After(cutoff) {
				continue
			}
			a := byRule[e.Rule]
			if a == nil {
				a = &agg{nodes: map[string]bool{}}
				byRule[e.Rule] = a
			}
			a.nodes[nodeID] = true
			a.flags++
			if e.Severity >= 3 {
				a.critical++
			}
		}
	}
	out := FleetRules{TotalNodes: len(s.nodes), Rules: []RuleAggregate{}}
	for rule, a := range byRule {
		ids := make([]string, 0, len(a.nodes))
		for id := range a.nodes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out.Rules = append(out.Rules, RuleAggregate{
			Rule: rule, Nodes: len(a.nodes), NodeIDs: ids,
			Flags24h: a.flags, Critical24h: a.critical,
		})
	}
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].Nodes != out.Rules[j].Nodes {
			return out.Rules[i].Nodes > out.Rules[j].Nodes
		}
		if out.Rules[i].Critical24h != out.Rules[j].Critical24h {
			return out.Rules[i].Critical24h > out.Rules[j].Critical24h
		}
		if out.Rules[i].Flags24h != out.Rules[j].Flags24h {
			return out.Rules[i].Flags24h > out.Rules[j].Flags24h
		}
		return out.Rules[i].Rule < out.Rules[j].Rule
	})
	return out
}

// flagSeverity reads the severity integer out of a flag payload (dropped by
// the old rollup — it is the difference between "flags happened" and
// "criticals are firing").
func flagSeverity(payload json.RawMessage) int {
	var flag struct {
		Severity int `json:"severity"`
	}
	if json.Unmarshal(payload, &flag) != nil {
		return 0
	}
	return flag.Severity
}

// incidentSeverity maps an incident's risk string onto the flag severity
// scale so windowed criticals can span both kinds.
func incidentSeverity(payload json.RawMessage) int {
	switch strings.ToUpper(summarize(payload, "risk", 20)) {
	case "CRITICAL":
		return 3
	case "HIGH":
		return 2
	default:
		return 1
	}
}

// summarize extracts one field from an opaque payload for the rollup line.
func summarize(payload json.RawMessage, field string, max int) string {
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		if len(v) > max {
			v = v[:max] + "…"
		}
		return v
	}
	return ""
}

// nodeRank orders cards by operator priority: what needs action first.
func nodeRank(st *NodeState, now time.Time) int {
	switch {
	case st.PostureState == "critical":
		return 0
	case st.PostureState == "attention":
		return 1
	case livenessState(st, now) != "":
		return 2
	case st.HasStatus:
		return 3 // heartbeat says all-clear
	default:
		return 4 // legacy event-only node, nothing actionable
	}
}

// displayName is the operator-facing node title: hostname when known.
func (st *NodeState) displayName() string {
	if st.Hostname != "" {
		return st.Hostname
	}
	return st.NodeID
}

// sortNodesSnapshot copies the rollup into operator-priority order with
// windowed counts recomputed as of now.
func (s *Store) sortNodesSnapshotLocked(now time.Time) []*NodeState {
	out := make([]*NodeState, 0, len(s.nodes))
	for _, rt := range s.nodes {
		cp := *rt.state
		cp.Flags24h, cp.CriticalFlags24h, cp.Incidents24h = windowCounts(rt.recent, now)
		cp.Gaps = rt.gapCount(now)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := nodeRank(out[i], now), nodeRank(out[j], now)
		if ri != rj {
			return ri < rj
		}
		if out[i].displayName() != out[j].displayName() {
			return out[i].displayName() < out[j].displayName()
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

// Rollup returns a stable-ordered snapshot of the node states.
func (s *Store) Rollup() []*NodeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortNodesSnapshotLocked(time.Now())
}

// Sessions returns every node's sessions as one cross-node list, newest
// activity first, with each node's hostname and labels attached so the view
// can group by env/role without a second lookup. Ended sessions are included
// within each node's maxNodeSessions bound, but they sort below live ones.
func (s *Store) Sessions() []FleetSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []FleetSession{}
	for nodeID, rt := range s.nodes {
		hostname := rt.state.Hostname
		labels := rt.state.Labels
		for _, sess := range rt.sessions {
			fs := FleetSession{NodeID: nodeID, Hostname: hostname, Labels: labels, sessionPayload: sess}
			out = append(out, fs)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		li, lj := out[i].Status != "ended", out[j].Status != "ended"
		if li != lj {
			return li // live sessions first
		}
		return out[i].LastSeenAt > out[j].LastSeenAt
	})
	return out
}

// Query replays one node's envelopes from disk, newest first, optionally
// filtered by kind.
func (s *Store) Query(nodeID string, kinds map[string]bool, limit int) []envelopeFile {
	return s.log.Query(nodeID, kinds, limit)
}

// liveness thresholds. Heartbeat nodes report every ~60s by default, so
// three missed intervals is genuinely suspicious; legacy event-only nodes
// keep the old lenient thresholds (a quiet node might genuinely be idle).
const (
	statusStaleAfter = 3 * time.Minute
	statusGoneAfter  = 10 * time.Minute
	legacyStaleAfter = 10 * time.Minute
	legacyGoneAfter  = 20 * time.Minute
)

// livenessState classifies a node as "", "stale", or "gone" from its
// heartbeat (or, for legacy nodes, event) cadence.
func livenessState(st *NodeState, now time.Time) string {
	staleAfter, goneAfter := legacyStaleAfter, legacyGoneAfter
	if st.HasStatus {
		staleAfter, goneAfter = statusStaleAfter, statusGoneAfter
	}
	switch age := now.Sub(st.LastSeen); {
	case age > goneAfter:
		return "gone"
	case age > staleAfter:
		return "stale"
	default:
		return ""
	}
}

// --- JSONL reference implementation of envelopeLog ---

const (
	// logMaxBytes: a node's live log never grows past this unless one line is larger.
	logMaxBytes = 16 << 20
	// logKeepRotated: at most this many rotated files are kept per node.
	logKeepRotated = 8
	// Encoding may escape one input byte as six (for example, '<' in a
	// payload). Allow the largest webhook plus the on-disk wrapper.
	maxLogLine   = 6*maxEnvelopeBody + 128
	logReadBlock = 64 << 10
)

// jsonlLog keeps one live file per node, <node>.jsonl, plus rotated files
// <node>.<seq>.jsonl where a higher seq is newer. Node ids never contain a
// dot, so the two name forms cannot collide. maxBytes <= 0 disables rotation.
type jsonlLog struct {
	dir      string
	maxBytes int64
	keep     int
	mu       sync.RWMutex // Serializes rotation with opening query snapshots.

	checkpointed   map[string]int
	saveCheckpoint func(root *os.Root, node string, through int) error
}

func newJSONLLog(dir string, maxBytes int64, keep int) *jsonlLog {
	return &jsonlLog{dir: dir, maxBytes: maxBytes, keep: keep}
}

func liveName(node string) string {
	return node + ".jsonl"
}

func rotatedName(node string, seq int) string {
	return fmt.Sprintf("%s.%06d.jsonl", node, seq)
}

// rotatedSeqs lists the node's rotated sequence numbers, oldest first.
func rotatedSeqs(root *os.Root, node string) ([]int, error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	var seqs []int
	for _, e := range entries {
		n, seq, rotated, ok := parseLogName(e.Name())
		if ok && rotated && n == node && !e.IsDir() {
			seqs = append(seqs, seq)
		}
	}
	sort.Ints(seqs)
	return seqs, nil
}

// parseLogName splits a log file name into node id and rotation sequence.
func parseLogName(name string) (node string, seq int, rotated, ok bool) {
	base, found := strings.CutSuffix(name, ".jsonl")
	if !found {
		return "", 0, false, false
	}
	i := strings.LastIndexByte(base, '.')
	if i < 0 {
		return base, 0, false, true
	}
	n, err := strconv.Atoi(base[i+1:])
	if err != nil || n < 0 {
		return "", 0, false, false
	}
	return base[:i], n, true, true
}

// openEnvelopeLog confines file access to the configured storage root and
// admits only regular logs. Nonblocking open keeps a replaced file from
// stalling the collector before its type can be checked.
func openEnvelopeLog(root *os.Root, name string, flags int) (*os.File, error) {
	f, err := root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("envelope log must be a regular file")
	}
	return f, nil
}

// Append writes the envelope as one JSON line to the node's live file,
// rotating it first when the line would take it past maxBytes.
func (l *jsonlLog) Append(env Envelope, receivedAt string) error {
	line, err := json.Marshal(envelopeFile{ReceivedAt: receivedAt, Envelope: env})
	if err != nil {
		return err
	}
	if len(line) > maxLogLine {
		return fmt.Errorf("envelope record exceeds %d bytes", maxLogLine)
	}
	line = append(line, '\n')
	node := sanitize(env.NodeID)

	l.mu.Lock()
	defer l.mu.Unlock()
	root, err := os.OpenRoot(l.dir)
	if err != nil {
		return fmt.Errorf("open log root: %w", err)
	}
	defer root.Close()
	if err := l.rotateIfNeeded(root, node, int64(len(line))); err != nil {
		return err
	}
	f, err := openEnvelopeLog(root, liveName(node), os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return fmt.Errorf("open append: %w", err)
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// rotateIfNeeded renames a non-empty live file that cannot take the incoming
// bytes. With no live file it also resumes interrupted retention.
func (l *jsonlLog) rotateIfNeeded(root *os.Root, node string, incoming int64) error {
	if l.maxBytes <= 0 {
		return nil
	}
	st, err := root.Lstat(liveName(node))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat live log: %w", err)
	}
	if st != nil && (!st.Mode().IsRegular() || st.Size() == 0 || st.Size()+incoming <= l.maxBytes) {
		return nil
	}
	seqs, err := rotatedSeqs(root, node)
	if err != nil {
		return fmt.Errorf("list rotated logs: %w", err)
	}
	if st != nil {
		last := l.checkpointed[node]
		if len(seqs) > 0 {
			last = max(last, seqs[len(seqs)-1])
		}
		if last >= math.MaxInt-1 {
			return fmt.Errorf("rotation sequence exhausted for %s", node)
		}
		next := last + 1
		if err := root.Rename(liveName(node), rotatedName(node, next)); err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
		seqs = append(seqs, next)
	}
	return l.prune(root, node, seqs)
}

func (l *jsonlLog) prune(root *os.Root, node string, seqs []int) error {
	if len(seqs) <= l.keep {
		return nil
	}
	through := seqs[len(seqs)-1]
	if l.checkpointed[node] < through {
		// The live file has just been archived (or is absent on recovery).
		// The in-memory rollup includes every record through this sequence.
		if l.saveCheckpoint == nil {
			return errors.New("rotation requires a rollup checkpoint")
		}
		if err := l.saveCheckpoint(root, node, through); err != nil {
			return fmt.Errorf("save rollup checkpoint: %w", err)
		}
		l.checkpointed[node] = through
	}
	for _, seq := range seqs[:len(seqs)-l.keep] {
		if err := root.Remove(rotatedName(node, seq)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("prune rotated log: %w", err)
		}
	}
	return nil
}

// replay restores durable rollups and applies logs newer than their
// checkpoints in order, with each node's live file last.
func (l *jsonlLog) replay(s *Store) error {
	root, err := os.OpenRoot(l.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	l.checkpointed = make(map[string]int)
	type logFile struct {
		name, node string
		seq        int
	}
	var files []logFile
	for _, e := range entries {
		if node, ok := strings.CutSuffix(e.Name(), checkpointSuffix); ok {
			through, err := s.restoreCheckpoint(root, e.Name())
			if err != nil {
				return fmt.Errorf("restore %s: %w", e.Name(), err)
			}
			l.checkpointed[node] = through
			continue
		}
		node, seq, rotated, ok := parseLogName(e.Name())
		if !e.Type().IsRegular() || !ok {
			continue
		}
		if !rotated {
			seq = math.MaxInt
		}
		files = append(files, logFile{e.Name(), node, seq})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].node != files[j].node {
			return files[i].node < files[j].node
		}
		return files[i].seq < files[j].seq
	})
	for _, lf := range files {
		if through, ok := l.checkpointed[lf.node]; ok && lf.seq <= through {
			continue
		}
		f, err := openEnvelopeLog(root, lf.name, os.O_RDONLY)
		if err != nil {
			return fmt.Errorf("open replay log %s: %w", lf.name, err)
		}
		err = scanLinesForward(f, func(line []byte) {
			var rec envelopeFile
			if json.Unmarshal(line, &rec) == nil {
				s.applyOnce(rec.Envelope, rec.ReceivedAt, false)
			}
		})
		f.Close()
		if err != nil {
			return fmt.Errorf("replay %s: %w", lf.name, err)
		}
	}
	return nil
}

// scanLinesForward skips oversized lines without discarding the rest of the
// segment. It retains at most one bounded record between reads.
func scanLinesForward(r io.Reader, fn func([]byte)) error {
	reader := bufio.NewReaderSize(r, logReadBlock)
	var line []byte
	skipping := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
			return err
		}
		if err == nil {
			fragment = fragment[:len(fragment)-1]
		}
		if !skipping {
			if len(line)+len(fragment) > maxLogLine {
				skipping = true
			} else if len(line) == 0 && err != bufio.ErrBufferFull {
				fn(fragment)
			} else {
				line = append(line, fragment...)
				if err != bufio.ErrBufferFull {
					fn(line)
				}
			}
		}
		if err != bufio.ErrBufferFull {
			line = line[:0]
			skipping = false
		}
		if err == io.EOF {
			return nil
		}
	}
}

type querySegment struct {
	file *os.File
	size int64
}

// querySegments opens the files before releasing the rotation lock. Reads
// through these descriptors survive renames and removals, and fixed end
// offsets exclude subsequent appends to the live file.
func (l *jsonlLog) querySegments(node string) []querySegment {
	l.mu.RLock()
	defer l.mu.RUnlock()

	root, err := os.OpenRoot(l.dir)
	if err != nil {
		return nil
	}
	defer root.Close()
	names := []string{liveName(node)}
	seqs, _ := rotatedSeqs(root, node)
	for i := len(seqs) - 1; i >= 0; i-- {
		names = append(names, rotatedName(node, seqs[i]))
	}

	segments := make([]querySegment, 0, len(names))
	for _, name := range names {
		f, err := openEnvelopeLog(root, name, os.O_RDONLY)
		if err != nil {
			continue
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			continue
		}
		segments = append(segments, querySegment{file: f, size: st.Size()})
	}
	return segments
}

// Query returns up to limit matching envelopes, newest first (limit <= 0
// means all). It reads the snapshot backwards and stops once it has enough.
func (l *jsonlLog) Query(nodeID string, kinds map[string]bool, limit int) []envelopeFile {
	segments := l.querySegments(sanitize(nodeID))
	defer func() {
		for _, segment := range segments {
			segment.file.Close()
		}
	}()

	var out []envelopeFile
	for _, segment := range segments {
		done := scanLinesReverse(segment.file, segment.size, func(line []byte) bool {
			var rec envelopeFile
			if json.Unmarshal(line, &rec) != nil {
				return false
			}
			if rec.Envelope.NodeID != "" && rec.Envelope.NodeID != nodeID {
				return false
			}
			if len(kinds) > 0 && !kinds[rec.Envelope.Kind] {
				return false
			}
			out = append(out, rec)
			return limit > 0 && len(out) >= limit
		})
		if done {
			break
		}
	}
	return out
}

// scanLinesReverse calls fn for each non-empty bounded line before end, last
// line first. A line spanning blocks is accumulated in reverse byte order.
func scanLinesReverse(f *os.File, end int64, fn func(line []byte) (stop bool)) bool {
	buf := make([]byte, logReadBlock)
	var carry []byte
	skipping := false
	for pos := end; pos > 0; {
		n := min(pos, int64(len(buf)))
		pos -= n
		if _, err := f.ReadAt(buf[:n], pos); err != nil {
			return false
		}
		data := buf[:n]
		for {
			i := bytes.LastIndexByte(data, '\n')
			fragment := data[i+1:]
			if !skipping {
				switch {
				case len(carry)+len(fragment) > maxLogLine:
					carry, skipping = carry[:0], true
				case i >= 0 && len(carry) == 0:
					if len(fragment) > 0 && fn(fragment) {
						return true
					}
				default:
					offset := len(carry)
					carry = append(carry, fragment...)
					slices.Reverse(carry[offset:])
					if i >= 0 {
						slices.Reverse(carry)
						if fn(carry) {
							return true
						}
						carry = carry[:0]
					}
				}
			}
			if i < 0 {
				break
			}
			data = data[:i]
			skipping = false
		}
	}
	slices.Reverse(carry)
	return !skipping && len(carry) > 0 && fn(carry)
}

// sanitize keeps a node id from escaping the store directory (it arrives in a
// header an operator provisioned, but defense in depth costs one regexp).
func sanitize(nodeID string) string {
	clean := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return -1
	}, nodeID)
	if clean == "" {
		clean = "unknown-node"
	}
	return clean
}
