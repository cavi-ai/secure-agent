package main

// Hot-reload of the local advisor: the menubar edits config.yaml on every
// Settings change ("Enable advisor", model switch, mode change). The daemon
// previously required a relaunch to pick it up — a Settings toggle should
// take effect within one poll cycle, so a light file watcher swaps the
// advisor stack live. Guard modes/fingerprint modes are read per-request by
// their own subsystems and are not part of this swap.
import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
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

// watchAdvisorConfig polls config.yaml and re-configures the advisor stack
// live on change. Poll (not fsnotify): the menubar writes atomically, so a
// 2s check is cheap and race-proof across save/rename. Only the advisor
// config is swapped — the rest of the daemon's config (paths, firewall,
// guard) is deliberately static for the daemon's lifetime.
func watchAdvisorConfig(ctx context.Context, path string, st *store.Store,
	stk *advisorStackHolder) {

	var lastKey string
	check := func() {
		data, err := config.Load(path)
		if err != nil {
			// A half-written or corrupt config must NEVER disturb the live
			// advisor: keep the current stack, log once per state change.
			if lastKey != "err" {
				log.Printf("advisor config reload skipped (config unreadable: %v) — keeping current state", err)
				lastKey = "err"
			}
			return
		}
		key := advisorConfigKey(data.Advisor)
		if key == lastKey {
			return
		}
		lastKey = key
		_ = stk.Load()
		// Stop the old subscriber cleanly before swapping (its Run loop is
		// supervised and exits on context cancellation; swapping mid-flight
		// is safe because the drain loop re-loads the stack per event).
		// The old subscriber's supervised Run loop keeps its own queue — the
		// drain loop now routes to the NEW stack, so the old loop simply goes
		// inert (its Run exits cleanly at daemon shutdown). No close needed:
		// swapping is the signal.
		stk.Store(setupAdvisor(data, st))
		log.Printf("advisor config applied live (enabled=%v mode=%s model=%q)",
			data.Advisor.Enabled, map[bool]string{true: "managed", false: "existing"}[data.Advisor.Managed], data.Advisor.Model)
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

// advisorConfigKey fingerprints the advisor-relevant config so a reload
// only swaps when something meaningful changed (not on every file touch).
func advisorConfigKey(a config.AdvisorConfig) string {
	return a.Endpoint + "|" + a.Model + "|" + a.ManagedModel + "|" +
		boolStr(a.Enabled) + "|" + boolStr(a.Managed) + "|" + a.Timeout.String()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}


