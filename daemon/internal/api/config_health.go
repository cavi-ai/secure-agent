package api

import (
	"regexp"
	"sync"
)

// configHealth is the config overlay's state. boot is the problem found at
// start: the settings it failed to set use built-in defaults until a restart,
// because firewall, guard and paths load only at start. reload is the latest
// hot-reload failure; the running settings are kept while it is set.
type configHealth struct {
	mu           sync.Mutex
	boot, reload string
}

// yamlValueRE is a value a YAML error quotes ("cannot unmarshal !!str `x`"),
// which may be a credential from the overlay.
var yamlValueRE = regexp.MustCompile("`[^`]*`")

func configProblem(err error) string {
	if err == nil {
		return ""
	}
	return yamlValueRE.ReplaceAllString(err.Error(), "a value")
}

// SetConfigBootProblem records the overlay problem found at start; nil means
// the overlay loaded in full or does not exist.
func (a *API) SetConfigBootProblem(err error) {
	a.config.mu.Lock()
	defer a.config.mu.Unlock()
	a.config.boot = configProblem(err)
}

// SetConfigReloadProblem records the latest hot-reload result; nil clears it.
func (a *API) SetConfigReloadProblem(err error) {
	a.config.mu.Lock()
	defer a.config.mu.Unlock()
	a.config.reload = configProblem(err)
}

func (a *API) configProblems() (boot, reload string) {
	a.config.mu.Lock()
	defer a.config.mu.Unlock()
	return a.config.boot, a.config.reload
}

func checkConfig(f doctorFacts) (string, string) {
	switch {
	case f.configBoot != "" && f.configReload != "":
		return doctorFail, "at start: " + f.configBoot + "; latest reload skipped: " + f.configReload
	case f.configBoot != "":
		return doctorFail, "at start: " + f.configBoot + "; the settings it could not set use built-in defaults until restart"
	case f.configReload != "":
		return doctorFail, "latest reload skipped, the running settings are kept: " + f.configReload
	}
	return doctorPass, "config.yaml loaded"
}
