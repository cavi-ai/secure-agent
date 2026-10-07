package api

import (
	"strings"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// configHealth is the config overlay's state. boot is the problem found at
// start: the settings it failed to set started on built-in defaults, and
// firewall, guard and paths keep them until a restart because they load only
// at start. reload is the latest hot-reload failure; the running settings
// are kept while it is set. Both are config.SafeError text. restart names
// the start-only settings the file changed since start.
type configHealth struct {
	mu           sync.Mutex
	boot, reload string
	restart      []string
}

// SetConfigRestartNeeded records the start-only settings (config.yaml keys)
// the latest good reload found changed since start; empty clears it.
func (a *API) SetConfigRestartNeeded(keys []string) {
	a.config.mu.Lock()
	defer a.config.mu.Unlock()
	a.config.restart = append([]string(nil), keys...)
}

// SetConfigBootProblem records the overlay problem found at start; nil means
// the overlay loaded in full or does not exist.
func (a *API) SetConfigBootProblem(err error) {
	a.config.mu.Lock()
	defer a.config.mu.Unlock()
	a.config.boot = config.SafeError(err)
}

// SetConfigReloadProblem records the latest hot-reload result; nil clears it.
func (a *API) SetConfigReloadProblem(err error) {
	a.config.mu.Lock()
	defer a.config.mu.Unlock()
	a.config.reload = config.SafeError(err)
}

func (a *API) configProblems() (boot, reload string, restart []string) {
	a.config.mu.Lock()
	defer a.config.mu.Unlock()
	return a.config.boot, a.config.reload, a.config.restart
}

// checkConfig fails while a boot or reload problem stands, or while the file
// holds start-only settings the running daemon does not. A reload that read
// the same unchanged problem as boot is reported once, as the boot one.
func checkConfig(f doctorFacts) (string, string) {
	const bootTail = "; settings it could not set started on built-in defaults, and firewall, guard and paths keep them until restart"
	var parts []string
	switch {
	case f.configBoot != "" && f.configReload != "" && f.configReload != f.configBoot:
		parts = append(parts, "at start: "+f.configBoot+bootTail, "latest reload skipped: "+f.configReload)
	case f.configBoot != "":
		parts = append(parts, "at start: "+f.configBoot+bootTail)
	case f.configReload != "":
		parts = append(parts, "latest reload skipped, the running settings are kept: "+f.configReload)
	}
	if len(f.configRestart) > 0 {
		parts = append(parts, "changed since start, applied after restart: "+strings.Join(f.configRestart, ", "))
	}
	if len(parts) == 0 {
		return doctorPass, "config.yaml loaded"
	}
	return doctorFail, strings.Join(parts, "; ")
}
