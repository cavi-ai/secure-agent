package model

import "time"

// InterventionReceipt records a local process operation independently of its
// later observations. It contains identities and numeric telemetry, no payloads.
type InterventionReceipt struct {
	ID            string               `json:"id"`
	SessionID     string               `json:"session_id,omitempty"`
	SessionKey    string               `json:"session_key"`
	SourceID      string               `json:"source_id,omitempty"`
	Revision      int64                `json:"revision"`
	Kind          string               `json:"kind"`
	RootPID       int32                `json:"root_pid"`
	RootStartedAt time.Time            `json:"root_started_at"`
	RequestedAt   time.Time            `json:"requested_at"`
	AppliedAt     time.Time            `json:"applied_at,omitzero"`
	Status        string               `json:"status"`
	Verification  string               `json:"verification"`
	VerifiedBy    string               `json:"verified_by,omitempty"`
	Error         string               `json:"error,omitempty"`
	Before        InterventionSample   `json:"before"`
	After         []InterventionSample `json:"after"`
	Targets       []ProcessIdentity    `json:"targets"`
	Limits        []string             `json:"limits"`
}

type ProcessIdentity struct {
	PID       int32     `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

type InterventionSample struct {
	At                    time.Time `json:"at"`
	RSSBytes              *uint64   `json:"rss_bytes,omitempty"`
	CPUPercent            *float64  `json:"cpu_percent,omitempty"`
	HostAvailableBytes    *uint64   `json:"host_available_bytes,omitempty"`
	HostCPUPercent        *float64  `json:"host_cpu_percent,omitempty"`
	HostCapacity          string    `json:"host_capacity,omitempty"`
	CapturedFamilyPresent bool      `json:"captured_family_present"`
}
