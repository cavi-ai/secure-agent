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
	SessionID      string               `json:"session_id,omitempty"`
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
	At time.Time `json:"at"`
	// EndedAt is set when the activity spans time (a tool call that returned,
	// or one still running at capture): it matches a growth interval it
	// overlaps, not only one it started in.
	EndedAt time.Time `json:"ended_at,omitzero"`
	Kind    string    `json:"kind"`
	PID     int32     `json:"pid"`
	Process string    `json:"process,omitempty"`
	Summary string    `json:"summary"`
	// Ref names a stored record that is completed in place after capture (a
	// tool call's start row gains its status and duration), so re-enrichment
	// replaces the earlier copy instead of keeping both.
	Ref string `json:"ref,omitempty"`
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

// episodeActivityRank orders the kinds a growth headline names first: the
// agent's own actions explain a memory rise more directly than a connection.
var episodeActivityRank = map[string]int{
	"tool": 0, "model": 1, "process-start": 2, "process": 3, "file": 4,
	"guard": 5, "security": 5, "turn": 6, "network": 7,
}

func activityRank(kind string) int {
	if rank, ok := episodeActivityRank[kind]; ok {
		return rank
	}
	return len(episodeActivityRank)
}

// AttachEpisodeActivity bounds evidence and identifies the largest observed
// sample-to-sample memory increase. Its wording is intentionally temporal:
// "while" communicates co-occurrence without claiming causation. The
// interval is matched against every activity before the list is bounded, and
// the activities it matched are kept.
func AttachEpisodeActivity(episode Episode, activities []EpisodeActivity) Episode {
	activities = append([]EpisodeActivity(nil), activities...)
	sort.SliceStable(activities, func(i, j int) bool { return activities[i].At.Before(activities[j].At) })
	episode.Correlations = nil
	from, to, largest := steepestRise(episode.Session.Samples)
	if largest == 0 {
		episode.Activities = boundEpisodeActivities(activities, nil)
		return episode
	}

	concurrent := map[int]bool{}
	lead := -1
	for i, activity := range activities {
		end := activity.At
		if activity.EndedAt.After(end) {
			end = activity.EndedAt
		}
		if end.Before(from.At) || activity.At.After(to.At) {
			continue
		}
		concurrent[i] = true
		if activity.Summary != "" && (lead < 0 || activityRank(activity.Kind) < activityRank(activities[lead].Kind)) {
			lead = i
		}
	}
	summary := fmt.Sprintf("Memory rose %s in %s", formatEpisodeBytes(largest), formatEpisodeDuration(to.At.Sub(from.At)))
	if lead >= 0 {
		summary += " while " + strings.TrimSuffix(activities[lead].Summary, ".")
		if others := len(concurrent) - 1; others == 1 {
			summary += " (and 1 other recorded activity)"
		} else if others > 1 {
			summary += fmt.Sprintf(" (and %d other recorded activities)", others)
		}
	} else {
		summary += "; no matching activity was recorded in that interval"
	}
	episode.Correlations = []EpisodeCorrelation{{
		Summary: summary + ".", Confidence: "observed-correlation", From: from.At, To: to.At,
		RSSDeltaBytes: largest, ActivityCount: len(concurrent),
	}}
	episode.Activities = boundEpisodeActivities(activities, concurrent)
	return episode
}

// steepestRise returns the consecutive sample pair with the largest memory
// increase; largest is 0 when memory never rose between two samples.
func steepestRise(samples []Sample) (from, to Sample, largest uint64) {
	samples = append([]Sample(nil), samples...)
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].At.Before(samples[j].At) })
	for i := 1; i < len(samples); i++ {
		if samples[i].RSSBytes <= samples[i-1].RSSBytes {
			continue
		}
		if delta := samples[i].RSSBytes - samples[i-1].RSSBytes; delta > largest {
			largest, from, to = delta, samples[i-1], samples[i]
		}
	}
	return from, to, largest
}

// boundEpisodeActivities keeps at most episodeActivityLimit activities in
// time order: every one in keep first (the newest of them when they alone
// exceed the limit), then the newest of the rest.
func boundEpisodeActivities(activities []EpisodeActivity, keep map[int]bool) []EpisodeActivity {
	if len(activities) <= episodeActivityLimit {
		return activities
	}
	selected := make([]bool, len(activities))
	room := episodeActivityLimit
	for i := len(activities) - 1; i >= 0 && room > 0; i-- {
		if keep[i] {
			selected[i] = true
			room--
		}
	}
	for i := len(activities) - 1; i >= 0 && room > 0; i-- {
		if !selected[i] {
			selected[i] = true
			room--
		}
	}
	bounded := make([]EpisodeActivity, 0, episodeActivityLimit)
	for i, activity := range activities {
		if selected[i] {
			bounded = append(bounded, activity)
		}
	}
	return bounded
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
