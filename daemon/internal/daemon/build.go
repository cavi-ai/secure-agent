package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentask"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/otlp"
	"github.com/cavi-ai/secure-agent/daemon/internal/proxy"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

// Options are the composition inputs that are not part of config.Config.
type Options struct {
	// ConfigPath is where the live config was loaded from. Empty disables the
	// hot-reload watcher and the resource-policy writer (both need a path to
	// persist to).
	ConfigPath string
}

// Components is the fully-wired daemon: every subsystem built, every collector
// started. The caller owns its lifetime: wait for a shutdown trigger, then call
// Shutdown. Build is the composition root; main() is CLI parsing plus process
// lifecycle, not component construction.
type Components struct {
	cfg   config.Config
	store *store.Store
	bus   *bus.Bus

	// started goroutines and their shutdown handles.
	drainDone <-chan struct{}
	fleetPub  *fleet.Publisher
	otlp      *otlp.Exporter

	deltaHub         *api.DeltaHub
	resourceEpisodes *resourceEpisodeWriter

	cancel       context.CancelFunc
	shutdownOnce sync.Once
}

// writeCwdOverrides serializes per-project guard policies for the stdlib-only
// hook to read, beside this daemon's socket.
func writeCwdOverrides(cfg config.Config) {
	if err := config.WriteCwdOverrides(config.CwdOverridesPath(cfg), cfg.DirectoryGuard.CwdOverrides); err != nil {
		log.Printf("failed to write guard cwd overrides: %v", err)
	}
}

// Build resolves and wires every component from cfg, starting the collectors
// and servers. Returns a Components the caller shuts down. On failure it tears
// down whatever it had already built before returning the error.
func Build(parent context.Context, cfg config.Config, opts Options) (*Components, error) {
	ctx, cancel := context.WithCancel(parent)
	c := &Components{cfg: cfg, cancel: cancel}

	writeCwdOverrides(cfg)

	st, err := store.Open(cfg.DBPath, cfg.JSONLPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open store: %w", err)
	}
	c.store = st
	st.SetEventRetention(cfg.Retention.ConnEvent, cfg.Retention.Event)

	b := bus.New(2048)
	c.bus = b

	procSource := agents.NewProcSource()
	tagger := agents.New(cfg, procSource)
	tagger.Refresh()
	resourceTracker, resourceEpisodes, resourceControl := buildResourceStack(cfg, st, tagger)
	c.resourceEpisodes = resourceEpisodes

	classifier := sensitive.New(cfg)
	correlator := correlate.New(tagger, classifier, cfg)

	// Session resolver: attributes every event to a durable session at
	// ingest (hook handshake > transcript > process tree).
	resolver := session.NewResolver(st, tagger)

	repairStoredRows(st)

	// Typed deltas: SSE clients patch state from these; /snapshot is for
	// initial load and reconciliation only.
	deltaHub := api.NewDeltaHub()
	c.deltaHub = deltaHub
	tagger.SetOnTagged(reattributeUntaggedFlags(st, deltaHub, time.Now))
	// postureHook is armed once the API server exists (it owns posture).
	postureHook := &postureHookHolder{}

	// Stable per-install fleet identity (used by /fleet and webhook payloads).
	// Must run before the sinks are built: they capture api.NodeID.
	api.LoadNodeID(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "node-id"))

	fleetPub, fleetCfgLive, otlpExp := buildFleetAndOTLP(cfg)
	c.fleetPub = fleetPub
	c.otlp = otlpExp

	// Session changes reach every consumer: the console delta stream, the
	// fleet wire (cross-node sessions), and OTLP (trace backends).
	resolver.OnSessionChange = func(sess model.Session) {
		deltaHub.Publish(api.Delta{Type: "session", Data: sess})
		fleetPub.Publish(fleet.EventSession, sess)
		otlpExp.SessionSpan(sess)
	}

	// Local triage advisor (opt-in): flags/incidents are offered to it from
	// the drain loop; it never touches the enforcement path.
	advisorStk := &advisorStackHolder{}
	advisorStk.Store(setupAdvisor(cfg, st, deltaHub, postureHook.run))

	// Operator price table from config.yaml, applied before any collector
	// emits a model call; the config watcher re-applies it on change.
	applyPricing(cfg)

	// Supervisor with a shared health registry so /status reports each
	// collector's real state (running / restarting / abandoned). Coverage
	// heartbeats (last_produced) are carried across restarts from the state
	// file: a rebuild must not buy forty quiet minutes while the boot grace
	// hides a collector that died before the restart.
	supReg := supervise.NewRegistry()
	supReg.LoadLastProduced(loadLastProduced(cfg.DBPath))
	sup := supervise.New(supReg)
	persistLastProduced(cfg.DBPath, supReg) // seed the file so it always exists

	// Drain bus and correlate/persist (drainDone closes once every delivered
	// event has been persisted — shutdown waits for it).
	c.drainDone = startDrainLoop(b.Subscribe(), st, correlator, fleetPub, resolver, deltaHub, otlpExp,
		func() { postureHook.run() },
		func() *advisor.Subscriber { return advisorStk.Load().Sub })

	// Periodic process tagger refresh: 5s while idle, 1s while agents live.
	go runResourceLoop(ctx, tagger, resolver, resourceTracker, resourceControl, resourceEpisodes, st, cfg.DBPath, supReg)

	// Firewall engine + persisted overrides, used by the proxy for egress
	// inspection and surfaced as per-rule stats in status.
	fw := setupFirewall(cfg)

	allowlistStore, muteStore := wireEgressOverrides(cfg, correlator, advisorStk)
	st.SetAllowlistSource(allowlistStore.Load)

	var proxyServer *proxy.ProxyServer
	if cfg.ProxyEnabled {
		proxyServer = setupProxy(cfg, b, fw.Engine)
	}

	// Supervisor with a shared health registry so /status reports each collector's
	// real state (running / restarting / abandoned) instead of a blanket "running".
	statusFn := buildStatusFn(proxyServer, tagger, correlator, fw.Engine, supReg, st, time.Now(),
		func() advisor.HealthSnapshot { return advisorStk.Load().Sub.Health() },
		fleetConfigured(cfg.Fleet.Webhooks), collect.SpoolAvailable())

	// Start Control API. Every dependency is resolved here, once: the API no
	// longer exposes twenty optional setters that must be called in the right
	// order after New.
	guardBroker := guard.NewBroker(time.Duration(guardBrokerMS(cfg.DirectoryGuard.PromptDeadlineMS)) * time.Millisecond)
	notifyRuleStore := correlate.NewNotifyRuleStore(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "notify-rules.json"))
	notifyScopeStore := correlate.NewNotifyScopeStore(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "notify-scopes.json"))

	// Peer-credential gating on the control socket: kernel-attested pid/uid per
	// connection. Owner uid gets reads, tagged agent pids may ask the guard for
	// decisions. /kill is restricted to recognized agent processes regardless of
	// caller. The owning app (the menubar that launched this daemon) is pinned
	// as the only mutating client; direct launches (ppid = shell) keep
	// owner-uid mutation so headless/ssh management still works.
	agentPIDSet := taggedPIDSet(tagger)
	uiPID := owningUIPID()

	retriageFuncs, hostAssessFuncs, guardAdvisor, worktreeAdvisor := buildAdvisorHooks(st, advisorStk)
	projectAdvisor := func(req model.ProjectCleanupRequest) bool {
		if sub := advisorStk.Load().Sub; sub != nil {
			return sub.EnqueueProject(req)
		}
		return false
	}
	planFuncs := buildPlanFuncs(advisorStk)

	// Hermes Agent's collector is built before the API so /doctor reads its
	// state; startCollectors runs it.
	hermes := newHermesCollector(cfg, b, supReg, resolver)
	resourcePolicyUpdater := buildResourcePolicyUpdater(opts.ConfigPath, resourceControl)

	hunter := worktreehunter.New(st, "", worktreeOptions(cfg.Worktrees))
	cleanup := clutter.New(st, "", clutterPlaces(hunter))
	asker := agentask.New(st, "")
	apiServer := api.New(api.Deps{
		SocketPath:            cfg.SocketPath,
		Store:                 st,
		Killer:                &realKiller{},
		Status:                statusFn,
		BusDrops:              b.Dropped,
		Resources:             resourceControl.Snapshot,
		ResourceControl:       resourceControl,
		ResourcePolicyUpdater: resourcePolicyUpdater,
		Firewall: api.FirewallControl{
			Engine:      fw.Engine,
			Modes:       fw.Modes,
			Reload:      fw.Reload,
			Ingest:      fw.Ingest,
			Sources:     fw.Sources,
			BaseSources: fw.BaseSources,
		},
		Guard:        guardBroker,
		Correlator:   correlator,
		Allowlist:    allowlistStore,
		Mutes:        muteStore,
		NotifyRules:  notifyRuleStore,
		NotifyScopes: notifyScopeStore,
		Retriage:     retriageFuncs,
		Plan:         planFuncs,
		HostAssess:   hostAssessFuncs,
		GuardAdvisor: guardAdvisor,
		PeerChecker:  api.NewPeerChecker(),
		AgentPIDs:    agentPIDSet,
		UIPID:        uiPID,
		IsAgentPID: func(pid int32) bool {
			_, isAgent := tagger.Tag(pid)
			return isAgent
		},
		FleetSink:       fleetPub,
		FleetConfigured: len(cfg.Fleet.Webhooks) > 0,
		PublishEvent:    b.Publish,
		DeltaHub:        deltaHub,
		Hermes:          hermes.Status,
		Worktrees:       hunter,
		WorktreeAdvisor: worktreeAdvisor,
		Clutter:         cleanup,
		Asker:           asker,
		ProjectAdvisor:  projectAdvisor,
	})

	resourceControl.SetExecutor(makeResourceExecutor(apiServer, tagger, st))

	// Fleet heartbeat: posture + liveness pushed to every sink at boot, on a
	// ticker, and on posture-state transitions. Always armed — enrolling a
	// collector via config hot-reload activates it without a restart.
	startFleetHeartbeat(ctx, apiServer, statusFn, fleetPub, fleetCfgLive.Load)

	// Hot-reload: the menubar edits config.yaml on advisor/settings changes
	// and `secure-agent fleet enroll` writes fleet.webhooks; the daemon must
	// NOT require a relaunch for either. Watch the file and swap the advisor
	// stack / fleet sinks live within a poll cycle (guard modes read
	// per-request already). Started after the API server exists — the watcher
	// updates fleet_configured on it.
	if opts.ConfigPath != "" {
		go watchConfig(ctx, opts.ConfigPath, configWatchDeps{
			st: st, stk: advisorStk, pub: fleetPub, fleetCfg: fleetCfgLive,
			logDir: filepath.Dir(cfg.DBPath), apiServer: apiServer, resourceControl: resourceControl,
			initialConfig: &cfg, worktrees: hunter,
			deltaHub: deltaHub, postureChanged: postureHook.run,
		})
	}
	postureHook.fn = apiServer.PublishPostureIfChanged

	// The browser console's telemetry fetches are same-origin with the
	// dashboard, i.e. they land on the proxy's loopback HTTP port. Serve the
	// API there behind the console token (a credential agents never receive —
	// unlike the proxy token they carry for egress), so /dashboard/ shows live
	// data instead of a wall of 407s.
	if proxyServer != nil {
		consoleToken := proxy.LoadConsoleToken(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "console-token"))
		if consoleToken == "" {
			log.Printf("WARNING: console token unavailable; browser console API on the proxy port is disabled")
		}
		proxyServer.SetConsoleAPI(apiServer.ConsoleHandler())
	}
	go func() {
		if err := apiServer.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Printf("API server error: %v", err)
		}
	}()

	startCollectors(ctx, sup, supReg, cfg, b, tagger, resolver, advisorStk, proxyServer, fw.Engine, hermes)

	log.Printf("secure-agentd running on unix socket %s", cfg.SocketPath)
	return c, nil
}

// WaitForShutdown blocks until ctx is cancelled or the owning parent exits.
// The menu bar app that launches this daemon owns its lifetime and sends
// SIGTERM on quit; if that app dies abruptly (even via SIGKILL, which cannot
// be caught by it), this process is reparented to launchd (pid 1). Watching
// for the parent change guarantees the daemon never lingers as a hidden
// background process after its owner is gone. watchParentExit returns nil when
// launched directly by pid 1 (no owning parent to outlive).
func (c *Components) WaitForShutdown(ctx context.Context) {
	parentGone := watchParentExit(os.Getppid())
	select {
	case <-ctx.Done():
	case <-parentGone:
	}
}

// Shutdown stops the daemon in the order shutdown depends on: stop the
// collectors/servers, close the bus so the drain goroutine finishes buffered
// events, wait (bounded) for the drain, the fleet webhooks and the OTLP
// exporter, then release the store and episodic state. Idempotent.
func (c *Components) Shutdown() {
	c.shutdownOnce.Do(func() {
		log.Println("secure-agentd shutting down...")
		if c.cancel != nil {
			c.cancel() // stop collectors, API, and the tagger loop
		}
		if c.bus != nil {
			c.bus.Close() // close the subscriber channel so the drain goroutine finishes buffered events
		}
		if c.drainDone != nil {
			select {
			case <-c.drainDone: // all delivered events persisted
			case <-time.After(2 * time.Second): // bounded: never hang shutdown on a stuck write
				log.Println("secure-agentd: drain timed out; some buffered events may be unpersisted")
			}
		}
		// Give in-flight webhook deliveries a bounded window to land — a fleet
		// collector must not lose the final events to process exit.
		if c.fleetPub != nil {
			fleetDone := make(chan struct{})
			go func() { c.fleetPub.Wait(); close(fleetDone) }()
			select {
			case <-fleetDone:
			case <-time.After(3 * time.Second):
				log.Println("secure-agentd: webhook delivery wait timed out; some deliveries may be dropped")
			}
		}
		// Flush buffered OTLP spans so the final trace batch lands. Bounded like
		// the rest: a dead endpoint must not hold shutdown open.
		if c.otlp != nil {
			otlpDone := make(chan struct{})
			go func() { c.otlp.Wait(); close(otlpDone) }()
			select {
			case <-otlpDone:
			case <-time.After(3 * time.Second):
				log.Println("secure-agentd: OTLP export wait timed out; some spans may be dropped")
			}
		}
		if c.deltaHub != nil {
			c.deltaHub.Close()
		}
		if c.resourceEpisodes != nil {
			c.resourceEpisodes.Close()
		}
		if c.store != nil {
			c.store.Close()
		}
	})
}

type realKiller struct{}

func (k *realKiller) Kill(pid int32) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	// Terminate politely, then force. The automated resource ladder already
	// gives a session a grace window; a manual kill must not be a worse
	// citizen than the automatic one. SIGTERM lets the process flush state and
	// release locks; a stubborn process gets SIGKILL after the grace.
	log.Printf("secure-agentd: sending SIGTERM to pid %d", pid)
	if err := syscall.Kill(int(pid), syscall.SIGTERM); err != nil {
		// Already gone (ESRCH) or not ours (EPERM): report, don't escalate.
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		if err := syscall.Kill(int(pid), 0); err != nil {
			return nil // exited
		}
	}
	log.Printf("secure-agentd: pid %d ignored SIGTERM; issuing SIGKILL", pid)
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return err
	}
	return nil
}

// postureHookHolder defers arming the posture-delta hook until the API
// server exists (it owns posture computation); the drain loop starts first.
type postureHookHolder struct {
	fn func()
}

func (h *postureHookHolder) run() {
	if h.fn != nil {
		h.fn()
	}
}

// owningUIPID returns the pid of the owning menubar app, or 0. Pinned as the
// only mutating client — but only when the parent really is an .app binary. A
// direct launch from a shell must keep owner-uid mutation (headless/ssh
// management). ps(1) is spawned once at startup, not per request.
// coverageFilePath is where the coverage heartbeats persist, next to the
// event store: <db dir>/coverage.json.
func coverageFilePath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "coverage.json")
}

// loadLastProduced reads the previous run's coverage heartbeats. Best-effort:
// a missing or corrupt file is an empty map, never a startup failure.
func loadLastProduced(dbPath string) map[string]string {
	data, err := os.ReadFile(coverageFilePath(dbPath))
	if err != nil {
		return nil
	}
	out := map[string]string{}
	if json.Unmarshal(data, &out) != nil {
		return nil
	}
	return out
}

// persistLastProduced writes the registry's coverage heartbeats for the next
// run. Best-effort and cheap (a few hundred bytes on the tagger cadence).
func persistLastProduced(dbPath string, reg *supervise.Registry) {
	snap := reg.PersistLastProduced()
	if snap == nil {
		return
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	path := coverageFilePath(dbPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

func owningUIPID() int32 {
	ppid := os.Getppid()
	if ppid <= 1 {
		return 0
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(ppid), "-o", "comm=").Output()
	if err != nil {
		return 0
	}
	parentExe := strings.TrimSpace(string(out))
	if strings.Contains(parentExe, ".app/Contents/MacOS/") || strings.Contains(parentExe, ".app/Contents/Frameworks/") {
		return int32(ppid)
	}
	return 0
}

func firewallStats(e *firewall.Engine) map[string]firewall.RuleStat {
	if e == nil {
		return nil
	}
	return e.Stats()
}

// taggedPIDSet adapts the tagger's pid map to the API's allowlist shape.
// Shared by peer classification and /kill restriction.
func taggedPIDSet(tg *agents.Tagger) func() map[int32]struct{} {
	return func() map[int32]struct{} {
		tagged := tg.TaggedPIDs()
		pids := make(map[int32]struct{}, len(tagged))
		for pid := range tagged {
			pids[pid] = struct{}{}
		}
		return pids
	}
}

func listActiveAgents(tg *agents.Tagger) []api.AgentSummary {
	tagged := tg.TaggedPIDs()
	res := make([]api.AgentSummary, 0, len(tagged))
	for pid, info := range tagged {
		s := api.AgentSummary{
			PID:        pid,
			Name:       info.Name,
			Kind:       info.Kind,
			ExePath:    info.ExePath,
			CWD:        info.CWD,
			PPID:       info.PPID,
			RootPID:    info.RootPID,
			RSSBytes:   info.RSSBytes,
			CPUPercent: info.CPUPercent,
			IsOrphan:   info.IsOrphan,
		}
		if !info.StartedAt.IsZero() {
			s.StartedAt = info.StartedAt.UTC().Format(time.RFC3339Nano)
		}
		res = append(res, s)
	}
	return res
}

// --- Build stages ---

// buildResourceStack primes tracker, episode writer, and controller with a
// first observation so the API never serves an empty snapshot.
func buildResourceStack(cfg config.Config, st *store.Store, tagger *agents.Tagger) (*resource.Tracker, *resourceEpisodeWriter, *resource.Controller) {
	tracker := resource.NewTracker()
	episodes := newResourceEpisodeWriter(st)
	control := resource.NewController(resourcePolicy(cfg.ResourceControl), nil)
	control.SetPolicySet(resourcePolicySet(cfg.ResourceControl))
	now := time.Now()
	observeResources(tracker, tagger, st, now)
	control.Observe(tracker.Snapshot(), now)
	episodes.Observe(control.Snapshot())
	return tracker, episodes, control
}

// repairStoredRows re-resolves repo/branch on rows carrying the old basename
// heuristic and closes tool-call rows stranded at "running".
func repairStoredRows(st *store.Store) {
	if n := st.RepairSessionGitIdentity(session.GitInfoFor); n > 0 {
		log.Printf("sessions: re-resolved git identity on %d older rows", n)
	}
	if n := st.SweepStaleRunningCalls(time.Now().Add(-10 * time.Minute)); n > 0 {
		log.Printf("sessions: closed %d stale running tool-call rows", n)
	}
}

// buildFleetAndOTLP constructs the fleet webhook fan-out and the OTLP
// exporter (nil when unconfigured).
func buildFleetAndOTLP(cfg config.Config) (*fleet.Publisher, *fleetConfigHolder, *otlp.Exporter) {
	pub := fleet.NewPublisher()
	pub.ReplaceSinks(buildFleetSinks(cfg.Fleet, filepath.Dir(cfg.DBPath)))
	cfgLive := &fleetConfigHolder{}
	cfgLive.Store(cfg.Fleet)
	exp := otlp.New(otlp.Config{
		Endpoint: cfg.OTLP.Endpoint,
		Headers:  cfg.OTLP.Headers,
		Service:  cfg.OTLP.Service,
		Labels:   cfg.OTLP.Labels,
	}, api.NodeID, api.Version)
	return pub, cfgLive, exp
}

// runResourceLoop: tagger refresh (5s idle, 1s under agents), session sweep,
// resource observe, heartbeat persist.
func runResourceLoop(ctx context.Context, tagger *agents.Tagger, resolver *session.Resolver, tracker *resource.Tracker, control *resource.Controller, episodes *resourceEpisodeWriter, st *store.Store, dbPath string, supReg *supervise.Registry) {
	timer := time.NewTimer(agents.RefreshInterval(tagger.Any()))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			tagger.Refresh()
			now := time.Now()
			resolver.Sweep()
			observeResources(tracker, tagger, st, now)
			control.Observe(tracker.Snapshot(), now)
			episodes.Observe(control.Snapshot())
			persistLastProduced(dbPath, supReg)
			timer.Reset(agents.RefreshInterval(tagger.Any()))
		}
	}
}

// wireEgressOverrides attaches allowlist/mute stores to the correlator and
// arms advisor pre-assessment. The hook resolves the subscriber per call:
// hot-reload swaps the stack, and a stale capture panics on nil.
func wireEgressOverrides(cfg config.Config, correlator *correlate.Correlator, advisorStk *advisorStackHolder) (*correlate.AllowlistStore, *correlate.MuteStore) {
	stateDir := filepath.Dir(cfg.Firewall.Registry.SaltRef)
	allowlistStore := correlate.NewAllowlistStore(filepath.Join(stateDir, "allowlist-overrides.json"))
	correlator.SetAllowlistOverrides(func(agent string) []string { return allowlistStore.Load()[agent] })
	muteStore := correlate.NewMuteStore(filepath.Join(stateDir, "muted.json"))
	correlator.SetMuteChecker(muteStore.Muted)
	correlator.SetOnUninspected(func(agent, host string) {
		if sub := advisorStk.Load().Sub; sub != nil {
			sub.EnqueueHost(agent, host)
		}
	})
	return allowlistStore, muteStore
}

// buildAdvisorHooks wires the advisor-facing API closures; each resolves
// the subscriber per call (hot-reload swaps the stack).
func buildAdvisorHooks(st *store.Store, advisorStk *advisorStackHolder) (*api.RetriageFuncs, *api.HostAssessFuncs, func(model.GuardAssessmentRequest), func(model.WorktreeAdviceRequest) bool) {
	// Re-triage: look up the stored flag, enqueue through the CURRENT stack.
	retriage := &api.RetriageFuncs{
		LookupFlag: func(id string) (model.Flag, bool) { return st.GetFlag(id) },
		Enqueue: func(fl model.Flag) bool {
			if sub := advisorStk.Load().Sub; sub != nil {
				return sub.RetriageFlag(fl)
			}
			return false
		},
	}
	// On-demand host assessment: the console turns "what is this IP?" into
	// an advisor verdict the operator can act on. A cached verdict answers
	// immediately; a fresh assessment is queued so repeated clicks never
	// flood the model.
	hostAssess := &api.HostAssessFuncs{
		GetVerdict: func(agent, host string) (model.AdvisorVerdict, bool) {
			return st.AdvisorVerdictFor("host:"+agent+"|"+host, "host")
		},
		Enqueue: func(agent, host string) bool {
			if sub := advisorStk.Load().Sub; sub != nil {
				sub.EnqueueHost(agent, host)
				return true
			}
			return false
		},
	}
	// Guard advisor: each newly blocked prompt is offered for a
	// recommendation the operator reads before deciding. Advisory only —
	// the broker still blocks for the human; this never resolves a prompt.
	guardAdvisor := func(req model.GuardAssessmentRequest) {
		if sub := advisorStk.Load().Sub; sub != nil {
			sub.EnqueueGuard(req)
		}
	}
	// Worktree notes: queued on request through the current stack; false
	// when the advisor is off or its queue is full.
	worktreeAdvisor := func(req model.WorktreeAdviceRequest) bool {
		if sub := advisorStk.Load().Sub; sub != nil {
			return sub.EnqueueWorktree(req)
		}
		return false
	}
	return retriage, hostAssess, guardAdvisor, worktreeAdvisor
}

// buildResourcePolicyUpdater: nil without a config file (tests).
func buildResourcePolicyUpdater(configPath string, resourceControl *resource.Controller) func(config.ResourceControlConfig) error {
	if configPath == "" {
		return nil
	}
	return func(next config.ResourceControlConfig) error {
		if err := config.WriteResourceControl(configPath, next); err != nil {
			return err
		}
		resourceControl.SetPolicySet(resourcePolicySet(next))
		return nil
	}
}

// makeResourceExecutor revalidates every target against a baseline snapshot:
// a pid that left the session or was recycled is refused. Audited.
func makeResourceExecutor(apiServer *api.API, tagger *agents.Tagger, st *store.Store) func(resource.ControlAction) error {
	return func(action resource.ControlAction) error {
		var affected int
		baseline := tagger.TaggedPIDs()
		revalidate := func(pid int32) error {
			original, ok := baseline[pid]
			if !ok {
				return fmt.Errorf("pid %d left the recognized session", pid)
			}
			fresh, ok := tagger.TaggedPIDs()[pid]
			if !ok || !fresh.StartedAt.Equal(original.StartedAt) {
				return fmt.Errorf("pid %d identity changed before intervention", pid)
			}
			return nil
		}
		err := applyResourceProcessAction(action, baseline, func(action resource.ControlAction) error {
			expectedStarts := make(map[int32]time.Time)
			rootPID := action.RootPID
			if rootPID == 0 {
				if target, ok := baseline[action.TargetPID]; ok {
					rootPID = normalizedActionRoot(target)
				}
			}
			for pid, info := range baseline {
				if normalizedActionRoot(info) == rootPID {
					expectedStarts[pid] = info.StartedAt
				}
			}
			killed, killErr := apiServer.TerminateAgentTreeVerified(action.TargetPID, action.TargetStartedAt.Format(time.RFC3339Nano), expectedStarts)
			affected = len(killed)
			return killErr
		}, func(pid int32, signal syscall.Signal) error {
			if err := revalidate(pid); err != nil {
				return err
			}
			if err := syscall.Kill(int(pid), signal); err == nil {
				affected++
				return nil
			} else {
				return err
			}
		}, func(pid int32, nice int) error {
			if err := revalidate(pid); err != nil {
				return err
			}
			current, err := syscall.Getpriority(syscall.PRIO_PROCESS, int(pid))
			if err != nil {
				return err
			}
			if current >= nice {
				affected++
				return nil
			}
			if err := syscall.Setpriority(syscall.PRIO_PROCESS, int(pid), nice); err == nil {
				affected++
				return nil
			} else {
				return err
			}
		})
		detail := fmt.Sprintf("session=%s root_pid=%d action=%s processes=%d", action.SessionKey, action.RootPID, action.Kind, affected)
		if err != nil {
			detail += " error=" + err.Error()
		}
		auditAction := "resource-intervention"
		if action.Kind == string(resource.ActionTerminate) {
			auditAction = "resource-containment"
		}
		st.PutAudit(store.AuditEntry{Action: auditAction, Rule: action.Name, ToMode: action.Kind, Detail: detail})
		return err
	}
}

// startCollectors launches the supervised collectors. File telemetry:
//  1. Spool tail from the root ES LaunchDaemon (sanctioned path).
//  2. Direct eslogger child (root dev runs only).
//  3. Neither: degraded, not crash-looped; the transcript scanner remains.
func startCollectors(ctx context.Context, sup *supervise.Supervisor, supReg *supervise.Registry, cfg config.Config, b *bus.Bus, tagger *agents.Tagger, resolver *session.Resolver, advisorStk *advisorStackHolder, proxyServer *proxy.ProxyServer, fwEngine *firewall.Engine, hermes *collect.HermesCollector) {
	if proxyServer != nil {
		go sup.Run(ctx, "proxyserver", func(c context.Context) error {
			return proxyServer.Serve(c)
		})
	}

	switch {
	case collect.SpoolAvailable():
		tailer := collect.NewSpoolTailer(b)
		collect.ESServiceProbe = spoolServiceProbe(tailer)
		go sup.Run(ctx, "eslogger", func(c context.Context) error {
			tailer.OnProduce = func() { supReg.MarkProduced("eslogger") }
			return tailer.Run(c)
		})
		log.Printf("file telemetry: tailing privileged ES collector spool")
	case os.Geteuid() == 0 && collect.ESLoggerAvailable():
		go sup.Run(ctx, "eslogger", func(c context.Context) error {
			es := collect.NewESLogger(b)
			es.OnProduce = func() { supReg.MarkProduced("eslogger") }
			return es.Run(c)
		})
	default:
		log.Printf("file telemetry unavailable: ES requires a privileged collector (install it from Settings); transcript + network signals still active")
	}

	go sup.Run(ctx, "netsampler", func(c context.Context) error {
		ns := collect.NewNetSampler(b, tagger, cfg.NetSampleInterval, nil)
		ns.OnProduce = func() { supReg.MarkProduced("netsampler") }
		return ns.Run(c)
	})

	home, _ := os.UserHomeDir()
	go sup.Run(ctx, "transcript", func(c context.Context) error {
		ts := collect.NewTranscriptScanner(b, transcriptTailTargets(home, cfg.JSONLPath))
		ts.OffsetStatePath = filepath.Join(filepath.Dir(cfg.DBPath), "transcript-offsets.json")
		ts.ExtraTargets = func() []string { return codexSessionTargets(tagger, home) }
		ts.OnProduce = func() { supReg.MarkProduced("transcript") }
		ts.OnHandshake = func(h collect.Handshake) {
			hts, _ := time.Parse(time.RFC3339Nano, h.TS)
			resolver.HandleHandshake(session.Handshake{
				SessionID: h.SessionID, Harness: h.Harness, Workspace: h.Workspace,
				Repo: h.Repo, Branch: h.Branch, PID: h.PID, TS: hts,
			})
		}
		ts.OnSessionSeen = resolver.NoteTranscriptSession
		// A codex process holds its rollout open: the open-file probe joins
		// the rollout's session to that process's tree.
		joiner := &collect.RolloutJoiner{
			PIDs:       func() []int32 { return codexPIDs(tagger) },
			Probe:      collect.OpenRolloutFiles,
			SessionFor: ts.RolloutSession,
			Join:       resolver.JoinTranscriptPID,
		}
		go func() { _ = joiner.Run(c) }()
		// Transcript lines get the firewall's known-secret and typed-pattern
		// scan; a nil engine keeps the redact fallback (and avoids a typed-nil
		// interface).
		if fwEngine != nil {
			ts.TextScanner = fwEngine
		}
		return ts.Run(c)
	})

	// opencode keeps no JSONL transcripts — its trace lives in a SQLite DB,
	// so it is polled separately (read-only, watermarked). Absent DB → the
	// collector simply produces nothing and the coverage signal says so.
	oc := collect.NewOpencodeCollector(b, "", 0)
	oc.OnProduce = func() { supReg.MarkProduced("opencode") }
	oc.OnPoll = func(src string, wm int64) { supReg.MarkPolled("opencode", src, wm) }
	oc.OnSessionSeen = resolver.NoteTranscriptSession
	go sup.Run(ctx, "opencode", func(c context.Context) error {
		return oc.Run(c)
	})

	// openclaw keeps its conversations in lcm.db (SQLite) in its state
	// directory, polled the same way (read-only, watermarked). The directory
	// comes from openclaw_home, the environment, ~/.openclaw, or a running
	// openclaw process's executable path; none found → a silent no-op that
	// keeps looking. The watermark persists beside the store so history is
	// read once.
	ocl := collect.NewOpenclawCollector(b, "", 0)
	ocl.Configured = cfg.OpenclawHome
	ocl.StatePath = filepath.Join(filepath.Dir(cfg.DBPath), "openclaw-watermark.json")
	ocl.ProcessExes = func() []string { return openclawExes(tagger) }
	ocl.OnProduce = func() { supReg.MarkProduced("openclaw") }
	ocl.OnPoll = func(src string, wm int64) { supReg.MarkPolled("openclaw", src, wm) }
	ocl.OnSessionSeen = resolver.NoteTranscriptSession
	ocl.OnSessionEnded = resolver.EndTranscriptSession
	go sup.Run(ctx, "openclaw", func(c context.Context) error {
		return ocl.Run(c)
	})

	go sup.Run(ctx, "hermes", func(c context.Context) error {
		return hermes.Run(c)
	})

	if advisorStk.Load().Sub != nil {
		go sup.Run(ctx, "advisor", func(c context.Context) error {
			return advisorStk.Load().Sub.Run(c)
		})
	}
	if advisorStk.Load().Managed != nil {
		// The managed model server as a supervised collector: restart on
		// crash like any other, and kill it on shutdown so it never outlives
		// the daemon (advisor verdicts die with the app, by design).
		go sup.Run(ctx, "advisor-model", func(c context.Context) error {
			done := make(chan error, 1)
			go func() { done <- advisorStk.Load().Managed.Wait() }()
			select {
			case <-c.Done():
				_ = advisorStk.Load().Managed.Process.Kill()
				return nil
			case err := <-done:
				return err
			}
		})
	}
}

// newHermesCollector builds the Hermes Agent poller: state.db and every
// profile's state.db under hermes_home, $HERMES_HOME or ~/.hermes, read-only
// and watermarked (the watermarks persist beside the store); none found → a
// silent no-op that keeps looking.
func newHermesCollector(cfg config.Config, b *bus.Bus, supReg *supervise.Registry, resolver *session.Resolver) *collect.HermesCollector {
	h := collect.NewHermesCollector(b, 0)
	h.Configured = cfg.HermesHome
	h.StatePath = filepath.Join(filepath.Dir(cfg.DBPath), "hermes-watermark.json")
	h.OnProduce = func() { supReg.MarkProduced("hermes") }
	h.OnPoll = func(src string, wm int64) { supReg.MarkPolled("hermes", src, wm) }
	h.OnSessionSeen = func(s collect.HermesSighting) {
		resolver.NoteTranscriptSighting(session.TranscriptSighting{
			ID: s.ID, Harness: "hermes", Workspace: s.Workspace,
			Repo: s.Repo, Branch: s.Branch, ParentID: s.ParentID, TS: s.At,
		})
	}
	h.OnSessionEnded = resolver.EndTranscriptSession
	return h
}

// codexPIDs lists the live pids the tagger names codex.
func codexPIDs(tagger *agents.Tagger) []int32 {
	var out []int32
	for pid, info := range tagger.TaggedPIDs() {
		if info.Name == "codex" {
			out = append(out, pid)
		}
	}
	return out
}

// openclawExes lists the executable paths of tagged openclaw processes, the
// last-resort locator for openclaw's state directory.
func openclawExes(tagger *agents.Tagger) []string {
	var out []string
	for _, info := range tagger.TaggedPIDs() {
		if info.Name == "openclaw" && info.ExePath != "" {
			out = append(out, info.ExePath)
		}
	}
	return out
}

// spoolServiceProbe wraps collect.ESServiceState with the live tailer's
// drain stats, so a flooding writer (garbage lines drowning the per-tick
// budget) reads as a posture/doctor failure even while the root service and
// the tailer's own produce-heartbeat both look healthy.
func spoolServiceProbe(t *collect.SpoolTailer) func() (collect.ESServiceSnapshot, error) {
	return func() (collect.ESServiceSnapshot, error) {
		snap, err := collect.ESServiceState()
		if err != nil {
			return snap, err
		}
		stats := t.Stats()
		snap.Flooding = !stats.FloodSince.IsZero()
		snap.UnparsedShare = unparsedShare(stats)
		snap.BytesSkipped = stats.BytesSkipped
		return snap, nil
	}
}

// unparsedShare is the fraction of lines in the tailer's last drain that did
// not parse; 0 when the tailer has not drained anything yet.
func unparsedShare(s collect.SpoolStats) float64 {
	if s.Lines == 0 {
		return 0
	}
	return float64(s.Lines-s.Parsed) / float64(s.Lines)
}

// buildPlanFuncs connects /advisor/plan to the CURRENT advisor stack (config
// hot-reload swaps it); a nil subscriber reads as "advisor off".
func buildPlanFuncs(advisorStk *advisorStackHolder) *api.PlanFuncs {
	return &api.PlanFuncs{
		Enqueue: func(r advisor.PlanRequest) bool {
			if sub := advisorStk.Load().Sub; sub != nil {
				return sub.EnqueuePlan(r)
			}
			return false
		},
		Pending: func(subject string) bool {
			if sub := advisorStk.Load().Sub; sub != nil {
				return sub.PlanPending(subject)
			}
			return false
		},
		Ready: func() (bool, string) {
			sub := advisorStk.Load().Sub
			if sub == nil {
				return false, "the local advisor is off: enable it in Settings → Advisor"
			}
			if h := sub.Health(); h.CircuitOpen {
				return false, "the local advisor is paused after repeated failures: " + h.LastError
			}
			return true, ""
		},
	}
}

// clutterPlaces lists what the cleanup inventory searches: every repository
// the worktree hunter knows and each of its worktrees whose directory
// exists (orphans included; their files are the only copy).
func clutterPlaces(h *worktreehunter.Hunter) func(context.Context) []clutter.Place {
	return func(ctx context.Context) []clutter.Place {
		var out []clutter.Place
		for _, r := range h.Report(ctx, false).Repos {
			if r.Error == "" && !r.Bare {
				out = append(out, clutter.Place{Path: r.Path, Project: r.Path})
			}
			for _, w := range r.Worktrees {
				if w.State == worktreehunter.StateMain || w.State == worktreehunter.StatePrune {
					continue
				}
				out = append(out, clutter.Place{Path: w.Path, Project: r.Path, Worktree: w.Path})
			}
		}
		return out
	}
}
