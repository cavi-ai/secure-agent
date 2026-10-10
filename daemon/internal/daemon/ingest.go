package daemon

import (
	"log"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/otlp"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// ingestDeps names collaborators; optional publishers and callbacks default to
// no output. Store, Correlator, Resolver, and Tagger are required.
type ingestDeps struct {
	Store          *store.Store
	Correlator     *correlate.Correlator
	Resolver       *session.Resolver
	Tagger         *agents.Tagger
	Fleet          *fleet.Publisher
	Deltas         *api.DeltaHub
	OTLP           *otlp.Exporter
	PostureChanged func()
	Advisor        func() *advisor.Subscriber
	NewFlag        func(model.Flag)
}

// eventIngest owns persistence ordering and the bounded, best-effort egress
// projection queue. Stop waits for queued projections; bus closure belongs to
// the daemon, which drains its accepted deliveries before stopping ingest.
type eventIngest struct {
	deps           ingestDeps
	analyzer       *intel.Analyzer
	projection     chan store.EgressObservation
	projectionDone chan struct{}
	done           chan struct{}
	mu             sync.Mutex
	stopped        bool
	stopOnce       sync.Once
}

func newEventIngest(d ingestDeps) *eventIngest {
	if d.Store == nil || d.Correlator == nil || d.Resolver == nil || d.Tagger == nil {
		panic("event ingest requires store, correlator, resolver, and tagger")
	}
	i := &eventIngest{deps: d, analyzer: intel.NewAnalyzer(), projection: make(chan store.EgressObservation, 128), projectionDone: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(i.projectionDone)
		for observation := range i.projection {
			err := d.Store.RecordEgressObservation(observation)
			if d.Store.NoteEgressProjectionWrite(err) && d.PostureChanged != nil {
				d.PostureChanged()
			}
		}
	}()
	return i
}

func (i *eventIngest) Done() <-chan struct{} { return i.done }

func (i *eventIngest) Stop() {
	i.stopOnce.Do(func() {
		i.mu.Lock()
		i.stopped = true
		close(i.projection)
		i.mu.Unlock()
		<-i.projectionDone
		close(i.done)
	})
}

func runEventIngest(source <-chan event.Event, d ingestDeps) *eventIngest {
	i := newEventIngest(d)
	go func() {
		defer i.Stop()
		for e := range source {
			i.Feed(e)
		}
	}()
	return i
}

// Feed serializes attribution, correlation, persistence and publication. A
// stopped module refuses new input; callers never publish it as stored evidence.
func (i *eventIngest) Feed(e event.Event) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return false
	}
	d := i.deps
	st, cr, res, tagger := d.Store, d.Correlator, d.Resolver, d.Tagger
	pub, deltas, otlpExp := d.Fleet, d.Deltas, d.OTLP
	postureChanged, advGet, newFlag := d.PostureChanged, d.Advisor, d.NewFlag
	analyzer, projection := i.analyzer, i.projection
	// Attribute before anything else: the stored event, the flags it
	// triggers, and the incident all carry the session id.
	res.Resolve(&e)
	flags := cr.Observe(e)
	// File activity outside every agent family is kept only as the
	// evidence of a flag it raised: system-wide opens (indexers,
	// builds, the daemon itself) outnumber agent file activity by
	// orders of magnitude and would push it out of the per-kind
	// row budget.
	if len(flags) == 0 && isUnattributedFileEvent(e) {
		noteFileFeed(st, e)
		return true
	}
	e.Record = len(flags) > 0 || cr.SensitiveFile(e)
	eventWrite, eventErr := st.PutEvent(e)
	eventSaved := eventErr == nil && eventWrite.Changed
	healthChanged := eventWrite.HealthChanged
	noteFileFeed(st, e)
	if e.Kind == event.KindConnOpen && e.RemoteHost != "" && e.RemotePort > 0 {
		observation := store.EgressObservation{SessionID: e.SessionID, Host: e.RemoteHost, Protocol: "tcp", Port: e.RemotePort, At: e.TS}
		if tagger != nil {
			if info, ok := tagger.Tag(e.PID); ok {
				observation.Scope.Agent = info.Name
				observation.Scope.ExePath = info.ExePath
			}
		}
		if e.SessionID != "" {
			if sess, ok := st.GetSession(e.SessionID); ok {
				observation.Scope.Harness = sess.Harness
				observation.Scope.Workspace = sess.Workspace
			}
		}
		enqueueEgressProjection(projection, observation, st)
	}
	guardLifecycle := e.Kind == event.KindGuardPrompt || e.Kind == event.KindGuardResolved
	if deltas != nil && (eventSaved || guardLifecycle) {
		// Guard lifecycle keeps its own delta names (the menubar's
		// instant prompt path keys on them); everything else is a
		// generic typed event for timeline/console patching.
		kind := "event"
		if e.Kind == event.KindGuardPrompt || e.Kind == event.KindGuardResolved {
			kind = e.Kind.String()
		}
		de := e
		de.PriceClass = collect.EventPriceClass(e)
		deltas.Publish(api.Delta{Type: kind, Data: de})
	}
	// Traces cross the fleet wire too (opt-in per sink): a collector
	// showing cross-node sessions needs the tool/model calls, not just
	// the security events. Lossy by design — the publisher's in-flight
	// cap drops trace overflow before it can starve flags.
	if eventSaved && isTraceKind(e.Kind) {
		if pub != nil {
			pub.Publish(fleet.EventTrace, e)
		}
		otlpExp.TraceEvent(e)
	}
	for _, fl := range flags {
		if fl.SessionID == "" {
			fl.SessionID = e.SessionID
		}
		// Stamp the workspace so per-workspace notification scopes can
		// key on it without re-resolving the session later.
		if fl.Workspace == "" && fl.SessionID != "" {
			fl.Workspace = res.WorkspaceFor(fl.SessionID)
		}
		log.Printf("FLAG TRIGGERED [%d]: %s (pid %d agent %s)", fl.Severity, fl.Rule, fl.PID, fl.Agent)
		flagWrite, flagErr := st.PutFlag(fl)
		healthChanged = healthChanged || flagWrite.HealthChanged
		cr.ResolvePersistence(fl.ID, flagErr == nil && flagWrite.Changed)
		if flagErr != nil || !flagWrite.Changed {
			continue
		}
		if stored, ok := st.GetFlagWithAdvisor(fl.ID); ok {
			fl = stored
		}
		if deltas != nil {
			deltas.Publish(api.Delta{Type: "flag", Data: fl})
		}
		if pub != nil {
			pub.Publish(fleet.EventFlag, fl)
		}
		if advGet != nil {
			if adv := advGet(); adv != nil {
				adv.EnqueueFlag(fl)
			}
		}
		if newFlag != nil {
			newFlag(fl)
		}

		// Incidents aggregate: one per rule+session+subject, flags
		// become its evidence. The 323-identical-flags storm becomes
		// one incident with a count, not 323 reports.
		subject := intel.SubjectForFlag(fl)
		openID, found, lookupErr := st.FindOpenIncidentResult(fl.Rule, fl.SessionID, subject)
		if lookupErr != nil {
			log.Printf("store: open incident lookup failed: %v", lookupErr)
			continue
		}
		if found {
			if updated, ok := st.AggregateIntoIncident(openID, fl.ID, fl.TS); ok && deltas != nil {
				deltas.Publish(api.Delta{Type: "incident", Data: updated})
			}
			if postureChanged != nil {
				postureChanged()
			}
			continue
		}

		recentEvs := st.RecentEvents(100)
		report := analyzer.Analyze(fl, recentEvs)
		report.SessionID = fl.SessionID
		report.Subject = subject
		report.AggregateCount = 1
		if err := st.PutIncident(report); err != nil {
			continue
		}
		if deltas != nil {
			deltas.Publish(api.Delta{Type: "incident", Data: report})
		}
		log.Printf("INCIDENT CREATED [%s]: %s (Risk: %s, %d rotate items)", report.ID, report.Summary, report.Risk, len(report.RotateList))
		if pub != nil {
			pub.Publish(fleet.EventIncident, report)
		}
		if advGet != nil {
			if adv := advGet(); adv != nil {
				adv.EnqueueIncident(report)
			}
		}
	}
	if (healthChanged || len(flags) > 0 || guardLifecycle) && postureChanged != nil {
		postureChanged()
	}
	return true
}
