package model

import "time"

// Pattern caps: the identity lists name the busiest few, the covered ids
// bound one acknowledge request.
const (
	PatternListCap   = 5
	PatternFlagIDCap = 500
)

// Pattern is a repeating finding: every flag one agent raised under one rule
// on one subject in the window, served as one card with its cadence and
// identity instead of one row per flag.
type Pattern struct {
	// Key is agent|rule|subject; it is the id of the pattern's attention item.
	Key   string `json:"key"`
	Agent string `json:"agent"`
	Rule  string `json:"rule"`
	Title string `json:"title"`
	// Subject is the served subject: the file (display path) or, for egress
	// rules, the host.
	Subject EvidenceItem `json:"subject"`
	Count   int          `json:"count"`
	Unacked int          `json:"unacked"`
	First   time.Time    `json:"first"`
	Last    time.Time    `json:"last"`
	// MedianGapS is the median gap between consecutive flags; Bursts counts
	// gaps under 5 s.
	MedianGapS float64 `json:"median_gap_s"`
	Bursts     int     `json:"bursts"`
	// Cadence is the served phrase for MedianGapS ("about every 12 minutes").
	Cadence string `json:"cadence"`
	// Hourly is 24 equal buckets over the window ending now, oldest first
	// (one hour each for the default 24 h window).
	Hourly [24]int `json:"hourly"`
	// PIDs and Sessions list the busiest PatternListCap; the counts are the
	// distinct totals.
	PIDs         []int32  `json:"pids"`
	PIDCount     int      `json:"pid_count"`
	Sessions     []string `json:"sessions"`
	SessionCount int      `json:"session_count"`
	// Disposition is the worst among unacknowledged flags; acknowledged when
	// none is open.
	Disposition Disposition     `json:"disposition"`
	Summary     string          `json:"summary"`
	Actions     []ExplainAction `json:"actions"`
	// FlagIDs are the covered flags, open ones first, newest first, at most
	// PatternFlagIDCap.
	FlagIDs []string `json:"flag_ids"`
}
