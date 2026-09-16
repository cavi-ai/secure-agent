package resource

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	episodeSampleLimit  = 120 // ten minutes at the five-second sample cadence
	episodeProcessLimit = 64  // highest-RSS processes, always including the root
)

// Episode is a bounded, local post-mortem of a session under resource pressure.
// It retains the whole process family and enough trend history to explain what
// grew without keeping an unbounded copy of live telemetry.
type Episode struct {
	ID             int64     `json:"id,omitempty"`
	CapturedAt     time.Time `json:"captured_at"`
	Severity       string    `json:"severity"`
	DiagnosisCodes []string  `json:"diagnosis_codes"`
	Session        Session   `json:"session"`
}

type recordedPressure struct {
	signature string
	rssBytes  uint64
}

// Recorder emits an episode when pressure first appears, its diagnosis set
// changes, or memory rises another 25 percent. Healthy and exited sessions are
// forgotten so a later recurrence creates fresh evidence.
type Recorder struct {
	mu     sync.Mutex
	active map[string]recordedPressure
}

func NewRecorder() *Recorder {
	return &Recorder{active: make(map[string]recordedPressure)}
}

func (r *Recorder) Observe(snapshot Snapshot) []Episode {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := make(map[string]struct{}, len(snapshot.Sessions))
	episodes := make([]Episode, 0)
	for _, session := range snapshot.Sessions {
		seen[session.Key] = struct{}{}
		if len(session.Diagnoses) == 0 {
			delete(r.active, session.Key)
			continue
		}
		codes := make([]string, 0, len(session.Diagnoses))
		severity := "info"
		for _, diagnosis := range session.Diagnoses {
			codes = append(codes, diagnosis.Code)
			if severityRank(diagnosis.Severity) < severityRank(severity) {
				severity = diagnosis.Severity
			}
		}
		sort.Strings(codes)
		signature := strings.Join(codes, ",")
		previous, exists := r.active[session.Key]
		escalated := exists && previous.rssBytes > 0 && session.RSSBytes > previous.rssBytes && session.RSSBytes-previous.rssBytes >= previous.rssBytes/4
		if !exists || previous.signature != signature || escalated {
			episodes = append(episodes, Episode{
				CapturedAt: snapshot.ObservedAt, Severity: severity, DiagnosisCodes: codes,
				Session: boundedSessionCopy(session),
			})
			r.active[session.Key] = recordedPressure{signature: signature, rssBytes: session.RSSBytes}
		}
	}
	for key := range r.active {
		if _, ok := seen[key]; !ok {
			delete(r.active, key)
		}
	}
	return episodes
}

// Retry clears a transition baseline after a queue or persistence failure so
// the next observation emits the still-active pressure state again.
func (r *Recorder) Retry(sessionKey string) {
	r.mu.Lock()
	delete(r.active, sessionKey)
	r.mu.Unlock()
}

func boundedSessionCopy(session Session) Session {
	copyOf := cloneSnapshot(Snapshot{Sessions: []Session{session}}).Sessions[0]
	if len(copyOf.Samples) > episodeSampleLimit {
		copyOf.Samples = append([]Sample(nil), copyOf.Samples[len(copyOf.Samples)-episodeSampleLimit:]...)
	}
	if len(copyOf.Processes) > episodeProcessLimit {
		sort.Slice(copyOf.Processes, func(i, j int) bool { return copyOf.Processes[i].RSSBytes > copyOf.Processes[j].RSSBytes })
		bounded := append([]Process(nil), copyOf.Processes[:episodeProcessLimit]...)
		rootIncluded := false
		for _, process := range bounded {
			rootIncluded = rootIncluded || process.PID == copyOf.RootPID
		}
		if !rootIncluded {
			for _, process := range copyOf.Processes[episodeProcessLimit:] {
				if process.PID == copyOf.RootPID {
					bounded[len(bounded)-1] = process
					break
				}
			}
		}
		copyOf.Processes = bounded
	}
	return copyOf
}
