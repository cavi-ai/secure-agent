package daemon

// Hot-reload of live-swappable config: the menubar edits config.yaml on every
// Settings change ("Enable advisor", model switch), and `secure-agent fleet
// enroll` writes fleet.webhooks. The daemon previously required a relaunch to
// pick either up — a Settings toggle or an enrollment should take effect
// within one poll cycle, so a light file watcher swaps the advisor stack and
// the fleet sink set live. Guard modes/fingerprint modes are read per-request
// by their own subsystems; paths and firewall stay boot-static.
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// advisorStackHolder is the atomic, swap-safe reference the drain loop and
// collector runners read per use — swapping the stack while the loop is
// mid-event is safe because Load() hands out a consistent snapshot.
type advisorStackHolder struct {
	v atomic.Value // advisorStack
}

func (h *advisorStackHolder) Load() advisorStack {
	if x := h.v.Load(); x != nil {
		return x.(advisorStack)
	}
	return advisorStack{}
}

func (h *advisorStackHolder) Store(s advisorStack) { h.v.Store(s) }

// configWatchDeps bundles everything the live config watcher may swap.
type configWatchDeps struct {
	st              *store.Store
	stk             *advisorStackHolder
	pub             *fleet.Publisher
	fleetCfg        *fleetConfigHolder
	logDir          string   // webhook delivery log dir (filepath.Dir(cfg.DBPath))
	apiServer       *api.API // SetFleetConfigured follows the webhook set
	resourceControl *resource.Controller
	initialConfig   *config.Config
}

// watchConfig polls config.yaml and re-configures the advisor stack and the
// fleet sinks live on change. Poll (not fsnotify): the menubar writes
// atomically, so a 2s check is cheap and race-proof across save/rename.
// Paths, firewall, and guard are deliberately boot-static.
func watchConfig(ctx context.Context, path string, deps configWatchDeps) {

	var lastAdvisorKey, lastFleetKey, lastResourceKey string
	if deps.initialConfig != nil {
		lastAdvisorKey = advisorConfigKey(deps.initialConfig.Advisor)
		lastFleetKey = fleetConfigKey(deps.initialConfig.Fleet)
		lastResourceKey = resourceConfigKey(deps.initialConfig.ResourceControl)
	}
	check := func() {
		// LoadStrict, not Load: a malformed overlay makes Load substitute
		// compiled-in defaults (enabled=false, default endpoint) — the
		// watcher would then "apply" those defaults and silently reconfigure
		// a working setup to wrong values. Strict keeps the current state.
		data, err := config.LoadStrict(path)
		if err != nil {
			// A half-written or corrupt config must NEVER disturb live
			// state: keep everything, log once per state change.
			if lastAdvisorKey != "err" {
				log.Printf("config reload skipped (config unreadable: %v) — keeping current state", err)
				lastAdvisorKey = "err"
			}
			return
		}
		if key := advisorConfigKey(data.Advisor); key != lastAdvisorKey {
			lastAdvisorKey = key
			// Swapping is the signal: the drain loop re-loads the stack per
			// event, so the old subscriber simply goes inert (its supervised
			// Run exits cleanly at daemon shutdown). No close needed.
			deps.stk.Store(setupAdvisor(data, deps.st))
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
			if deps.apiServer != nil {
				deps.apiServer.SetFleetConfigured(len(data.Fleet.Webhooks) > 0)
			}
			log.Printf("fleet config applied live (%d webhook(s), heartbeat %ds)",
				len(data.Fleet.Webhooks), data.Fleet.HeartbeatIntervalSec)
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

func resourceConfigKey(c config.ResourceControlConfig) string {
	b, _ := json.Marshal(c) // all fields are JSON-safe after config validation
	return string(b)
}

// advisorConfigKey fingerprints the advisor-relevant config so a reload
// only swaps when something meaningful changed (not on every file touch).
func advisorConfigKey(a config.AdvisorConfig) string {
	return a.Endpoint + "|" + a.Model + "|" + a.ManagedModel + "|" +
		boolStr(a.Enabled) + "|" + boolStr(a.Managed) + "|" + a.Timeout.String()
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
