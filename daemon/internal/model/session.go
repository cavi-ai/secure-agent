package model

import "time"

// Session is the durable spine: one harness run in one workspace, surviving
// process exit. Events, flags, episodes and guard decisions carry its id.
type Session struct {
	ID      string `json:"id"`
	Harness string `json:"harness"`
	// Workspace is the harness working directory; Repo/Branch are best-effort
	// (from the hook handshake's git probe; empty for process-tree sessions).
	Workspace string `json:"workspace,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Branch    string `json:"branch,omitempty"`
	// RootPID + RootStartedAt tie the session to its process tree while it
	// lives; both stay recorded after the tree exits.
	RootPID       int32  `json:"root_pid,omitempty"`
	RootStartedAt string `json:"root_started_at,omitempty"`
	// ParentID nests subagent sessions under their spawning session.
	ParentID string `json:"parent_id,omitempty"`
	// Origin names who spawned the session when it is not the user's own
	// harness: "<agent> (openclaw)" for a Codex rollout under an openclaw
	// agent's Codex home; empty otherwise.
	Origin     string     `json:"origin,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	// Status: active (events in the idle window), idle, ended.
	Status string `json:"status"`
	// Confidence records which resolution tier identified the session:
	// hook (handshake) > transcript (log path) > process-tree (heuristic).
	Confidence string `json:"confidence"`
}

// Session status values.
const (
	SessionActive = "active"
	SessionIdle   = "idle"
	SessionEnded  = "ended"
)

// Session confidence tiers, strongest first. Never downgrade.
const (
	ConfHook        = "hook"
	ConfTranscript  = "transcript"
	ConfProcessTree = "process-tree"
)

// StrongerConfidence reports whether a outranks b.
func StrongerConfidence(a, b string) bool {
	return confidenceRank(a) < confidenceRank(b)
}

func confidenceRank(c string) int {
	switch c {
	case ConfHook:
		return 0
	case ConfTranscript:
		return 1
	case ConfProcessTree:
		return 2
	default:
		return 3
	}
}
