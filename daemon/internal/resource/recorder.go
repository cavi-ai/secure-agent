package resource

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	episodeSampleLimit   = 120 // ten minutes at the five-second sample cadence
	episodeProcessLimit  = 64  // highest-RSS processes, always including the root
	episodeActivityLimit = 80  // newest correlated events retained per episode
)

// Episode is a bounded, local post-mortem of a session under resource pressure.
// It retains the whole process family and enough trend history to explain what
// grew without keeping an unbounded copy of live telemetry.
type Episode struct {
	ID             int64                `json:"id,omitempty"`
	CapturedAt     time.Time            `json:"captured_at"`
	Severity       string               `json:"severity"`
	DiagnosisCodes []string             `json:"diagnosis_codes"`
	ActivityStatus string               `json:"activity_status,omitempty"`
	Activities     []EpisodeActivity    `json:"activities,omitempty"`
	Correlations   []EpisodeCorrelation `json:"correlations,omitempty"`
	Host           *HostSnapshot        `json:"host,omitempty"`
	Session        Session              `json:"session"`
}

// EpisodeActivity is a bounded, redacted reference to activity observed from
// a process in the captured family. Summary is deliberately short and must
// never contain payloads or secret values.
type EpisodeActivity struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	PID     int32     `json:"pid"`
	Process string    `json:"process,omitempty"`
	Summary string    `json:"summary"`
}

// EpisodeCorrelation describes temporal evidence, not a causal conclusion.
// The confidence label is explicit so clients cannot accidentally present an
// event that occurred near a spike as proof that it caused the spike.
type EpisodeCorrelation struct {
	Summary       string    `json:"summary"`
	Confidence    string    `json:"confidence"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	RSSDeltaBytes uint64    `json:"rss_delta_bytes"`
	ActivityCount int       `json:"activity_count"`
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
			var host *HostSnapshot
			if snapshot.Host != nil {
				copyOf := cloneSnapshot(Snapshot{Host: snapshot.Host})
				host = copyOf.Host
			}
			episodes = append(episodes, Episode{
				CapturedAt: snapshot.ObservedAt, Severity: severity, DiagnosisCodes: codes,
				Host:    host,
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

// AttachEpisodeActivity bounds evidence and identifies the largest observed
// sample-to-sample memory increase. Its wording is intentionally temporal:
// "while" communicates co-occurrence without claiming causation.
func AttachEpisodeActivity(episode Episode, activities []EpisodeActivity) Episode {
	activities = append([]EpisodeActivity(nil), activities...)
	sort.SliceStable(activities, func(i, j int) bool { return activities[i].At.Before(activities[j].At) })
	if len(activities) > episodeActivityLimit {
		activities = append([]EpisodeActivity(nil), activities[len(activities)-episodeActivityLimit:]...)
	}
	episode.Activities = activities
	episode.Correlations = nil

	samples := append([]Sample(nil), episode.Session.Samples...)
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].At.Before(samples[j].At) })
	if len(samples) < 2 {
		return episode
	}
	var from, to Sample
	var largest uint64
	for i := 1; i < len(samples); i++ {
		if samples[i].RSSBytes <= samples[i-1].RSSBytes {
			continue
		}
		delta := samples[i].RSSBytes - samples[i-1].RSSBytes
		if delta > largest {
			largest, from, to = delta, samples[i-1], samples[i]
		}
	}
	if largest == 0 {
		return episode
	}

	concurrent := make([]EpisodeActivity, 0)
	for _, activity := range activities {
		if !activity.At.Before(from.At) && !activity.At.After(to.At) {
			concurrent = append(concurrent, activity)
		}
	}
	summary := fmt.Sprintf("Memory rose %s in %s", formatEpisodeBytes(largest), formatEpisodeDuration(to.At.Sub(from.At)))
	if len(concurrent) > 0 && concurrent[0].Summary != "" {
		summary += " while " + strings.TrimSuffix(concurrent[0].Summary, ".")
	} else {
		summary += "; no matching activity was recorded in that interval"
	}
	episode.Correlations = []EpisodeCorrelation{{
		Summary: summary + ".", Confidence: "observed-correlation", From: from.At, To: to.At,
		RSSDeltaBytes: largest, ActivityCount: len(concurrent),
	}}
	return episode
}

func formatEpisodeBytes(bytes uint64) string {
	const gib = uint64(1024 * 1024 * 1024)
	const mib = uint64(1024 * 1024)
	if bytes >= gib {
		return fmt.Sprintf("%.1f GiB", float64(bytes)/float64(gib))
	}
	return fmt.Sprintf("%.0f MiB", float64(bytes)/float64(mib))
}

func formatEpisodeDuration(duration time.Duration) string {
	duration = duration.Round(time.Second)
	if duration%time.Minute == 0 && duration >= time.Minute {
		return fmt.Sprintf("%dm", int(duration/time.Minute))
	}
	return duration.String()
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
