package resource

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
)

const (
	sampleInterval    = 5 * time.Second
	maxSessionSamples = 720

	heavyMemoryBytes = uint64(4 * 1024 * 1024 * 1024)
	idleMemoryBytes  = uint64(2 * 1024 * 1024 * 1024)
	growthBytes      = uint64(1024 * 1024 * 1024)
	runawayBytes     = uint64(1024 * 1024 * 1024)
)

type Snapshot struct {
	ObservedAt   time.Time     `json:"observed_at"`
	Host         *HostSnapshot `json:"host,omitempty"`
	RSSBytes     uint64        `json:"rss_bytes"`
	CPUPercent   float64       `json:"cpu_percent,omitempty"`
	ProcessCount int           `json:"process_count"`
	SessionCount int           `json:"session_count"`
	// InfraCount counts kind=infra sessions (IDEs, local model servers) —
	// shared infrastructure shown beside, never inside, SessionCount.
	InfraCount int              `json:"infra_count,omitempty"`
	Sessions   []Session        `json:"sessions"`
	Episodes   []Episode        `json:"episodes"`
	Control    *ControlSnapshot `json:"control,omitempty"`
}

type Session struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Kind is "agent" or "infra" (IDEs, local model servers). Infra sessions
	// render as shared infrastructure: no diagnoses, no reclaimable estimate,
	// not counted as sessions.
	Kind                  string          `json:"kind,omitempty"`
	Workspace             string          `json:"workspace,omitempty"`
	RootPID               int32           `json:"root_pid"`
	RootStartedAt         time.Time       `json:"root_started_at"`
	LastSeenAt            string          `json:"last_seen_at,omitempty"`
	RSSBytes              uint64          `json:"rss_bytes"`
	CPUPercent            float64         `json:"cpu_percent,omitempty"`
	ProcessCount          int             `json:"process_count"`
	OrphanCount           int             `json:"orphan_count"`
	EstimatedReclaimBytes uint64          `json:"estimated_reclaim_bytes,omitempty"`
	Processes             []Process       `json:"processes"`
	Samples               []Sample        `json:"samples"`
	Diagnoses             []Diagnosis     `json:"diagnoses"`
	Control               *SessionControl `json:"control,omitempty"`
}

type Process struct {
	Name       string    `json:"name"`
	ExePath    string    `json:"exe_path,omitempty"`
	CWD        string    `json:"cwd,omitempty"`
	PID        int32     `json:"pid"`
	PPID       int32     `json:"ppid"`
	StartedAt  time.Time `json:"started_at"`
	RSSBytes   uint64    `json:"rss_bytes"`
	CPUPercent float64   `json:"cpu_percent,omitempty"`
	IsOrphan   bool      `json:"is_orphan,omitempty"`
}

type Sample struct {
	At         time.Time `json:"at"`
	RSSBytes   uint64    `json:"rss_bytes"`
	CPUPercent float64   `json:"cpu_percent,omitempty"`
}

type Diagnosis struct {
	Code                  string   `json:"code"`
	Severity              string   `json:"severity"`
	Summary               string   `json:"summary"`
	Evidence              []string `json:"evidence"`
	Threshold             string   `json:"threshold"`
	Confidence            string   `json:"confidence"`
	EstimatedReclaimBytes uint64   `json:"estimated_reclaim_bytes,omitempty"`
	ProcessPID            int32    `json:"process_pid,omitempty"`
}

type Tracker struct {
	mu             sync.RWMutex
	hostSampleMu   sync.Mutex
	histories      map[string][]Sample
	snapshot       Snapshot
	hostSampler    hostSampler
	hostRaw        rawHostSample
	hostObservedAt time.Time
}

func NewTracker() *Tracker {
	return newTrackerWithHostSampler(newPlatformHostSampler())
}

func newTrackerWithHostSampler(sampler hostSampler) *Tracker {
	return &Tracker{histories: make(map[string][]Sample), hostSampler: sampler}
}

func (t *Tracker) Observe(infos map[int32]agents.AgentInfo, lastSeen map[int32]string, now time.Time) {
	var sampled *rawHostSample
	agentCPUTimes := make(map[int32]time.Duration, len(infos))
	for pid, info := range infos {
		agentCPUTimes[pid] = info.CPUTime
	}
	t.hostSampleMu.Lock()
	t.mu.RLock()
	due := t.hostObservedAt.IsZero() || now.Sub(t.hostObservedAt) >= sampleInterval
	t.mu.RUnlock()
	if due && t.hostSampler != nil {
		raw := t.hostSampler(agentCPUTimes)
		sampled = &raw
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if sampled != nil && (t.hostObservedAt.IsZero() || now.Sub(t.hostObservedAt) >= sampleInterval) {
		t.hostRaw = *sampled
		t.hostObservedAt = now
	}
	t.hostSampleMu.Unlock()

	rootStarts := make(map[int32]time.Time)
	for _, info := range infos {
		rootPID := normalizedRootPID(info)
		if info.PID == rootPID {
			rootStarts[rootPID] = info.StartedAt
		}
	}

	grouped := make(map[string]*Session)
	latestSeen := make(map[string]time.Time)
	for _, info := range infos {
		rootPID := normalizedRootPID(info)
		rootStart := rootStarts[rootPID]
		key := sessionKey(rootPID, rootStart)
		session := grouped[key]
		if session == nil {
			session = &Session{Key: key, RootPID: rootPID, RootStartedAt: rootStart, Kind: info.Kind}
			grouped[key] = session
		}

		process := Process{
			Name:       info.Name,
			ExePath:    info.ExePath,
			CWD:        info.CWD,
			PID:        info.PID,
			PPID:       info.PPID,
			StartedAt:  info.StartedAt,
			RSSBytes:   info.RSSBytes,
			CPUPercent: info.CPUPercent,
			IsOrphan:   info.IsOrphan,
		}
		session.Processes = append(session.Processes, process)
		session.RSSBytes += process.RSSBytes
		session.CPUPercent += process.CPUPercent
		session.ProcessCount++
		if process.IsOrphan {
			session.OrphanCount++
		}
		if seen, ok := parseTimestamp(lastSeen[info.PID]); ok && seen.After(latestSeen[key]) {
			latestSeen[key] = seen
			session.LastSeenAt = lastSeen[info.PID]
		}
	}

	sessions := make([]Session, 0, len(grouped))
	nextHistories := make(map[string][]Sample, len(grouped))
	for key, session := range grouped {
		sort.Slice(session.Processes, func(i, j int) bool {
			iRoot := session.Processes[i].PID == session.RootPID
			jRoot := session.Processes[j].PID == session.RootPID
			if iRoot != jRoot {
				return iRoot
			}
			return session.Processes[i].PID < session.Processes[j].PID
		})
		for _, process := range session.Processes {
			if process.PID == session.RootPID {
				session.Name = process.Name
				session.Workspace = process.CWD
				break
			}
		}
		if session.Name == "" && len(session.Processes) > 0 {
			session.Name = session.Processes[0].Name
		}
		if session.Workspace == "" {
			for _, process := range session.Processes {
				if process.CWD != "" {
					session.Workspace = process.CWD
					break
				}
			}
		}

		history := append([]Sample(nil), t.histories[key]...)
		if len(history) == 0 || now.Sub(history[len(history)-1].At) >= sampleInterval {
			history = append(history, Sample{At: now, RSSBytes: session.RSSBytes, CPUPercent: session.CPUPercent})
			if len(history) > maxSessionSamples {
				history = append([]Sample(nil), history[len(history)-maxSessionSamples:]...)
			}
		}
		nextHistories[key] = history
		session.Samples = append([]Sample(nil), history...)
		if session.Kind != "infra" {
			// Infra (IDEs, model servers) is shared infrastructure: monitored
			// and killable, but a 17 GB IDE must never read as "reclaimable
			// agent memory" — no diagnoses, no reclaim estimate.
			session.Diagnoses = diagnoseSession(*session, history, now)
			for _, diagnosis := range session.Diagnoses {
				if diagnosis.EstimatedReclaimBytes > session.EstimatedReclaimBytes {
					session.EstimatedReclaimBytes = diagnosis.EstimatedReclaimBytes
				}
			}
		}
		sessions = append(sessions, *session)
	}

	sort.Slice(sessions, func(i, j int) bool {
		left, right := impactScore(sessions[i]), impactScore(sessions[j])
		if left != right {
			return left > right
		}
		return sessions[i].Key < sessions[j].Key
	})

	snapshot := Snapshot{ObservedAt: now, Sessions: sessions}
	for _, session := range sessions {
		if session.Kind == "infra" {
			snapshot.InfraCount++
		} else {
			snapshot.SessionCount++
		}
		snapshot.RSSBytes += session.RSSBytes
		snapshot.CPUPercent += session.CPUPercent
		snapshot.ProcessCount += session.ProcessCount
	}
	host := deriveHostSnapshot(t.hostRaw, snapshot.RSSBytes)
	snapshot.Host = &host
	t.histories = nextHistories
	t.snapshot = snapshot
}

func (t *Tracker) Snapshot() Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return cloneSnapshot(t.snapshot)
}

func normalizedRootPID(info agents.AgentInfo) int32 {
	if info.RootPID != 0 {
		return info.RootPID
	}
	return info.PID
}

func sessionKey(rootPID int32, startedAt time.Time) string {
	return fmt.Sprintf("%d:%d", rootPID, startedAt.UnixNano())
}

func parseTimestamp(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil
}

func diagnoseSession(session Session, history []Sample, now time.Time) []Diagnosis {
	diagnoses := make([]Diagnosis, 0, 6)
	if session.RSSBytes >= heavyMemoryBytes {
		diagnoses = append(diagnoses, Diagnosis{
			Code: "heavy-memory", Severity: "critical", Summary: "Session is using at least 4 GiB of resident memory.",
			Evidence: []string{fmt.Sprintf("current RSS: %d bytes", session.RSSBytes)}, Threshold: "RSS >= 4 GiB", Confidence: "high", EstimatedReclaimBytes: session.RSSBytes,
		})
	}
	if session.CPUPercent >= 100 {
		diagnoses = append(diagnoses, Diagnosis{
			Code: "heavy-cpu", Severity: "critical", Summary: "Session is consuming at least one full CPU core.",
			Evidence: []string{fmt.Sprintf("current CPU: %.1f%%", session.CPUPercent)}, Threshold: "CPU >= 100%", Confidence: "high", EstimatedReclaimBytes: session.RSSBytes,
		})
	}

	cutoff := now.Add(-15 * time.Minute)
	var baseline *Sample
	for i := range history {
		if history[i].At.After(cutoff) {
			break
		}
		baseline = &history[i]
	}
	if baseline != nil && baseline.RSSBytes > 0 && session.RSSBytes >= baseline.RSSBytes {
		growth := session.RSSBytes - baseline.RSSBytes
		growthPercent := float64(growth) / float64(baseline.RSSBytes) * 100
		if growth >= growthBytes && growthPercent >= 25 {
			diagnoses = append(diagnoses, Diagnosis{
				Code: "rapid-growth", Severity: "warning", Summary: "Session memory grew by at least 1 GiB and 25% in 15 minutes.",
				Evidence: []string{fmt.Sprintf("15-minute growth: %d bytes (%.1f%%)", growth, growthPercent)}, Threshold: "15-minute growth >= 1 GiB and >= 25%", Confidence: "high", EstimatedReclaimBytes: growth,
			})
		}
	}

	if lastSeen, ok := parseTimestamp(session.LastSeenAt); ok && !lastSeen.After(cutoff) && session.RSSBytes >= idleMemoryBytes {
		diagnoses = append(diagnoses, Diagnosis{
			Code: "idle-heavy", Severity: "warning", Summary: "Session retains at least 2 GiB after 15 minutes without attributed activity.",
			Evidence: []string{fmt.Sprintf("last attributed activity: %s", session.LastSeenAt)}, Threshold: "idle >= 15 minutes and RSS >= 2 GiB", Confidence: "medium", EstimatedReclaimBytes: session.RSSBytes,
		})
	}

	for _, process := range session.Processes {
		if process.PID == session.RootPID || process.RSSBytes < runawayBytes || session.RSSBytes == 0 {
			continue
		}
		share := float64(process.RSSBytes) / float64(session.RSSBytes) * 100
		if share >= 60 {
			diagnoses = append(diagnoses, Diagnosis{
				Code: "runaway-child", Severity: "warning", Summary: "One child process holds at least 60% of session memory.",
				Evidence: []string{fmt.Sprintf("PID %d: %d bytes (%.1f%%)", process.PID, process.RSSBytes, share)}, Threshold: "child RSS >= 1 GiB and >= 60% of session RSS", Confidence: "high", EstimatedReclaimBytes: process.RSSBytes, ProcessPID: process.PID,
			})
			break
		}
	}

	if session.OrphanCount > 0 {
		var orphanBytes uint64
		for _, process := range session.Processes {
			if process.IsOrphan {
				orphanBytes += process.RSSBytes
			}
		}
		diagnoses = append(diagnoses, Diagnosis{
			Code: "orphan-drift", Severity: "warning", Summary: "Attributed processes remain after their parent disappeared.",
			Evidence: []string{fmt.Sprintf("orphan processes: %d", session.OrphanCount)}, Threshold: "any attributed orphan", Confidence: "high", EstimatedReclaimBytes: orphanBytes,
		})
	}

	sort.Slice(diagnoses, func(i, j int) bool {
		left, right := severityRank(diagnoses[i].Severity), severityRank(diagnoses[j].Severity)
		if left != right {
			return left < right
		}
		return diagnoses[i].Code < diagnoses[j].Code
	})
	return diagnoses
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}

func impactScore(session Session) float64 {
	memory := float64(session.RSSBytes) / float64(heavyMemoryBytes)
	cpu := session.CPUPercent / 100
	if cpu > memory {
		return cpu
	}
	return memory
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	copyOf := snapshot
	if snapshot.Host != nil {
		host := *snapshot.Host
		host.SystemCPUPercent = cloneFloat(snapshot.Host.SystemCPUPercent)
		host.NonAgentCPUPercent = cloneFloat(snapshot.Host.NonAgentCPUPercent)
		host.Load1 = cloneFloat(snapshot.Host.Load1)
		copyOf.Host = &host
	}
	copyOf.Sessions = make([]Session, len(snapshot.Sessions))
	for i, session := range snapshot.Sessions {
		copyOf.Sessions[i] = session
		copyOf.Sessions[i].Processes = append([]Process(nil), session.Processes...)
		copyOf.Sessions[i].Samples = append([]Sample(nil), session.Samples...)
		copyOf.Sessions[i].Diagnoses = make([]Diagnosis, len(session.Diagnoses))
		if session.Control != nil {
			control := *session.Control
			control.Violations = append([]Violation(nil), session.Control.Violations...)
			copyOf.Sessions[i].Control = &control
		}
		for j, diagnosis := range session.Diagnoses {
			copyOf.Sessions[i].Diagnoses[j] = diagnosis
			copyOf.Sessions[i].Diagnoses[j].Evidence = append([]string(nil), diagnosis.Evidence...)
		}
	}
	copyOf.Episodes = make([]Episode, len(snapshot.Episodes))
	for i, episode := range snapshot.Episodes {
		copyOf.Episodes[i] = episode
		if episode.Host != nil {
			host := *episode.Host
			host.SystemCPUPercent = cloneFloat(episode.Host.SystemCPUPercent)
			host.NonAgentCPUPercent = cloneFloat(episode.Host.NonAgentCPUPercent)
			host.Load1 = cloneFloat(episode.Host.Load1)
			copyOf.Episodes[i].Host = &host
		}
		copyOf.Episodes[i].DiagnosisCodes = append([]string(nil), episode.DiagnosisCodes...)
		copyOf.Episodes[i].Session = boundedSessionCopy(episode.Session)
	}
	return copyOf
}
