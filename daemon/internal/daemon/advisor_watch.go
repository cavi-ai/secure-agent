package daemon

// Hot-reload of live-swappable config: the menubar edits config.yaml on every
// Settings change ("Enable advisor", model switch), and `secure-agent fleet
// enroll` writes fleet.webhooks. The daemon previously required a relaunch to
// pick either up — a Settings toggle or an enrollment should take effect
// within one poll cycle, so a light file watcher swaps the advisor stack and
// the fleet sink set live. The operator price table (`pricing`) follows the
// same poll. Guard modes/fingerprint modes are read per-request by their own
// subsystems; paths and firewall stay boot-static.
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

// advisorStackHolder is the atomic, swap-safe reference the drain loop and
// collector runners read per use — swapping the stack while the loop is
// mid-event is safe because Load() hands out a consistent snapshot.
type advisorStackHolder struct {
	v      atomic.Value // advisorStack
	mu     sync.Mutex
	ctx    context.Context
	sup    *supervise.Supervisor
	cancel context.CancelFunc
	done   chan struct{}
	closed bool
}

func (h *advisorStackHolder) Load() advisorStack {
	if x := h.v.Load(); x != nil {
		return x.(advisorStack)
	}
	return advisorStack{}
}

func (h *advisorStackHolder) Store(s advisorStack) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		disposeAdvisor(s)
		return
	}
	h.stopLocked()
	h.v.Store(s)
	h.startLocked()
}

// Run owns each concrete generation. Reload cancels and joins the previous
// worker and model before starting its replacement, including enable-at-runtime.
func (h *advisorStackHolder) Run(ctx context.Context, sup *supervise.Supervisor) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.ctx, h.sup = ctx, sup
	h.startLocked()
	h.mu.Unlock()
	<-ctx.Done()
	h.Close()
}

func (h *advisorStackHolder) startLocked() {
	if h.ctx == nil || h.ctx.Err() != nil {
		return
	}
	s := h.Load()
	ctx, cancel := context.WithCancel(h.ctx)
	h.cancel, h.done = cancel, make(chan struct{})
	done, sup := h.done, h.sup
	go func() {
		var workers sync.WaitGroup
		if s.Sub != nil {
			workers.Add(1)
			go func() { defer workers.Done(); sup.Run(ctx, "advisor", s.Sub.Run) }()
		}
		if s.Managed != nil {
			workers.Add(1)
			go func() {
				defer workers.Done()
				exited := make(chan error, 1)
				go func() { exited <- s.Managed.Wait() }()
				waited := false
				defer func() {
					// Supervisor may see cancellation before entering the worker.
					if !waited {
						_ = s.Managed.Process.Kill()
						<-exited
					}
				}()
				sup.Run(ctx, "advisor-model", func(c context.Context) error {
					select {
					case <-c.Done():
						_ = s.Managed.Process.Kill()
						<-exited
						waited = true
						return nil
					case err := <-exited:
						waited = true
						if err == nil {
							err = fmt.Errorf("managed model exited")
						}
						// An exec.Cmd can only be waited once. A config reload
						// launches a fresh command; retrying this one cannot recover.
						return supervise.Permanent(err)
					}
				})
			}()
		}
		workers.Wait()
		close(done)
	}()
}

func disposeAdvisor(s advisorStack) {
	if s.Managed != nil {
		_ = s.Managed.Process.Kill()
		_ = s.Managed.Wait()
	}
}

func (h *advisorStackHolder) stopLocked() {
	if h.cancel != nil {
		h.cancel()
		<-h.done
		h.cancel, h.done = nil, nil
	} else {
		disposeAdvisor(h.Load())
	}
}

func (h *advisorStackHolder) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	h.stopLocked()
	h.v.Store(advisorStack{})
}

// configWatchDeps bundles everything the live config watcher may swap.
type configWatchDeps struct {
	st              *store.Store
	stk             *advisorStackHolder
	pub             *fleet.Publisher
	fleetCfg        *fleetConfigHolder
	logDir          string       // webhook delivery log dir (filepath.Dir(cfg.DBPath))
	apiServer       *api.API     // config reload problems for Doctor
	fleetOn         *atomic.Bool // fleet_configured for /status and /fleet
	resourceControl *resource.Controller
	worktrees       *worktreehunter.Hunter
	sysAgent        *sysagent.Agent
	tagger          *agents.Tagger // follows agents minus disabled_agents
	initialConfig   *config.Config
	// deltaHub/postureChanged follow the advisor stack into setupAdvisor so
	// a verdict landing after a config-driven advisor swap still gets the
	// immediate flag delta (see verdictPublishingSink in wire.go).
	deltaHub       *api.DeltaHub
	postureChanged func()
	advisorMask    func(string) (string, bool)
}

// watchConfig polls config.yaml and re-configures the advisor stack, the
// fleet sinks, resource control, the price table, worktrees, the system
// agent and the monitored agents (disabled_agents) live on change. Poll
// (not fsnotify): the menubar writes atomically, so a 2s check is cheap and
// race-proof across save/rename. Paths, firewall, and guard are deliberately
// boot-static.
func watchConfig(ctx context.Context, path string, deps configWatchDeps) {

	var lastAdvisorKey, lastFleetKey, lastResourceKey, lastPricingKey, lastWorktreesKey, lastSysAgentKey, lastAgentsKey string
	if deps.initialConfig != nil {
		lastAdvisorKey = advisorConfigKey(deps.initialConfig.Advisor)
		lastFleetKey = fleetConfigKey(deps.initialConfig.Fleet)
		lastResourceKey = resourceConfigKey(deps.initialConfig.ResourceControl)
		lastPricingKey = pricingConfigKey(*deps.initialConfig)
		lastWorktreesKey = worktreesConfigKey(deps.initialConfig.Worktrees)
		lastSysAgentKey = sysAgentConfigKey(deps.initialConfig.SystemAgent)
		lastAgentsKey = agentsConfigKey(deps.initialConfig.Agents)
	}
	check := func() {
		// LoadStrict, not Load: a malformed overlay makes Load substitute
		// compiled-in defaults (enabled=false, default endpoint) — the
		// watcher would then "apply" those defaults and silently reconfigure
		// a working setup to wrong values. Strict keeps the current state.
		data, err := config.LoadStrict(path)
		if deps.apiServer != nil {
			deps.apiServer.SetConfigReloadProblem(err)
		}
		if err != nil {
			// A half-written or corrupt config must NEVER disturb live
			// state: keep everything, log once per state change. Doctor
			// reports it until a reload succeeds.
			if lastAdvisorKey != "err" {
				log.Printf("config reload skipped (config unreadable: %s) — keeping current state", config.SafeError(err))
				lastAdvisorKey = "err"
			}
			return
		}
		if deps.apiServer != nil && deps.initialConfig != nil {
			deps.apiServer.SetConfigRestartNeeded(config.RestartSettings(*deps.initialConfig, data))
		}
		if key := advisorConfigKey(data.Advisor); key != lastAdvisorKey {
			lastAdvisorKey = key
			// Store transfers worker and managed-process ownership to the new stack.
			deps.stk.Store(setupAdvisor(data, deps.st, deps.deltaHub, deps.postureChanged, deps.advisorMask))
			log.Printf("advisor config applied live (enabled=%v mode=%s model=%q)",
				data.Advisor.Enabled, map[bool]string{true: "managed", false: "existing"}[data.Advisor.Managed], data.Advisor.Model)
		}
		if key := fleetConfigKey(data.Fleet); key != lastFleetKey {
			lastFleetKey = key
			// Atomic swap: in-flight deliveries on old sinks finish; new
			// Publishes route to the new set. The heartbeat loop reads the
			// holder per cycle, so interval/labels/hostname follow too.
			deps.pub.ReplaceSinks(buildFleetSinks(data.Fleet, deps.logDir))
			deps.fleetCfg.Store(data.Fleet)
			if deps.fleetOn != nil {
				deps.fleetOn.Store(fleetConfigured(data.Fleet.Webhooks))
			}
			log.Printf("fleet config applied live (%d webhook(s), heartbeat %ds)",
				len(data.Fleet.Webhooks), data.Fleet.HeartbeatIntervalSec)
		}
		if key := pricingConfigKey(data); key != lastPricingKey {
			lastPricingKey = key
			applyPricing(data, deps.st)
			log.Printf("pricing config applied live (%d model(s))", len(data.Pricing))
		}
		if key := worktreesConfigKey(data.Worktrees); key != lastWorktreesKey && deps.worktrees != nil {
			lastWorktreesKey = key
			deps.worktrees.SetOptions(worktreeOptions(data.Worktrees))
			log.Printf("worktrees config applied live (%d root(s), stale after %d days)",
				len(data.Worktrees.Roots), worktreeOptions(data.Worktrees).StaleDays)
		}
		if key := agentsConfigKey(data.Agents); key != lastAgentsKey && deps.tagger != nil {
			lastAgentsKey = key
			deps.tagger.SetAgents(data.Agents)
			log.Printf("monitored agents applied live (%d definition(s); disabled: %v)", len(data.Agents), data.DisabledAgents)
		}
		if key := sysAgentConfigKey(data.SystemAgent); key != lastSysAgentKey && deps.sysAgent != nil {
			lastSysAgentKey = key
			deps.sysAgent.SetConfig(data.SystemAgent)
			log.Printf("system agent config applied live (enabled=%v endpoint=%s model=%q harness_model=%q)",
				data.SystemAgent.Enabled, data.SystemAgent.Endpoint, data.SystemAgent.Model, data.SystemAgent.HarnessModel)
		}
		if key := resourceConfigKey(data.ResourceControl); key != lastResourceKey {
			lastResourceKey = key
			if deps.resourceControl != nil {
				applied := deps.resourceControl.SetPolicySet(resourcePolicySet(data.ResourceControl))
				if applied && deps.st != nil {
					deps.st.PutAudit(store.AuditEntry{Action: "resource-policy", ToMode: data.ResourceControl.Mode,
						Detail: fmt.Sprintf("rss=%dMiB cpu=%.0f%% sustain=%ds cooldown=%ds",
							data.ResourceControl.MaxRSSMB, data.ResourceControl.MaxCPUPercent,
							data.ResourceControl.SustainSeconds, data.ResourceControl.CooldownSeconds)})
				}
				if applied {
					log.Printf("resource control applied live (mode=%s rss=%dMiB cpu=%.0f%% sustain=%ds)",
						data.ResourceControl.Mode, data.ResourceControl.MaxRSSMB,
						data.ResourceControl.MaxCPUPercent, data.ResourceControl.SustainSeconds)
				}
			}
		}
	}
	check()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// applyPricing installs the operator price table, logs each entry the loader
// dropped, and prices stored calls the table now covers. Called at boot and
// by the watcher only on a change, so a malformed entry is logged once per
// load, not once per poll.
func applyPricing(cfg config.Config, st *store.Store) {
	for _, s := range cfg.PricingSkipped {
		log.Printf("config: pricing entry ignored (%s)", s)
	}
	collect.SetUserPrices(cfg.Pricing)
	if st == nil {
		return
	}
	if n := st.RepriceZeroCostCalls(collect.ModelCostUSD); n > 0 {
		log.Printf("pricing: priced %d stored model calls written without a price", n)
	}
}

// pricingConfigKey fingerprints the price table and its dropped entries.
func pricingConfigKey(c config.Config) string {
	b, _ := json.Marshal(struct {
		Prices  map[string][2]float64
		Skipped []string
	}{c.Pricing, c.PricingSkipped}) // prices are finite after config parsing
	return string(b)
}

func sysAgentConfigKey(c config.SystemAgentConfig) string {
	b, _ := json.Marshal(c)
	return string(b)
}

func agentsConfigKey(defs []config.AgentDef) string {
	b, _ := json.Marshal(defs)
	return string(b)
}

func worktreesConfigKey(c config.WorktreesConfig) string {
	b, _ := json.Marshal(c)
	return string(b)
}

// worktreeOptions maps the config key onto the hunter's options (0 stale
// days = the hunter's default).
func worktreeOptions(c config.WorktreesConfig) worktreehunter.Options {
	o := worktreehunter.Options{Roots: c.Roots, StaleDays: c.StaleDays}
	if o.StaleDays <= 0 {
		o.StaleDays = worktreehunter.DefaultStaleDays
	}
	return o
}

func resourceConfigKey(c config.ResourceControlConfig) string {
	b, _ := json.Marshal(c) // all fields are JSON-safe after config validation
	return string(b)
}

// advisorConfigKey fingerprints the advisor-relevant config so a reload
// only swaps when something meaningful changed (not on every file touch).
func advisorConfigKey(a config.AdvisorConfig) string {
	return a.Endpoint + "|" + a.Model + "|" + a.ManagedModel + "|" +
		boolStr(a.Enabled) + "|" + boolStr(a.Managed) + "|" + a.Timeout.String() + "|" + a.ClassifierEndpoint + "|" + a.ClassifierModel
}

// fleetConfigKey fingerprints the fleet-relevant config (webhooks, identity,
// cadence) so the watcher only rebuilds sinks on a real change.
func fleetConfigKey(f config.FleetConfig) string {
	var b strings.Builder
	b.WriteString(f.Hostname)
	b.WriteString("|")
	b.WriteString(strconv.Itoa(f.HeartbeatIntervalSec))
	b.WriteString("|")
	keys := make([]string, 0, len(f.Labels))
	for k := range f.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(f.Labels[k])
		b.WriteString(",")
	}
	b.WriteString("|")
	for _, w := range f.Webhooks {
		b.WriteString(w.URL)
		b.WriteString("@")
		b.WriteString(w.Secret)
		b.WriteString(":")
		b.WriteString(strings.Join(w.Events, ","))
		b.WriteString(";")
	}
	return b.String()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
