package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed defaults.yaml
var defaultBytes []byte

//go:embed guard-rules.json
var guardRulesBytes []byte

// GuardRuleDoc is the JSON the directory-guard hook and the correlator both
// read: rule ids, path globs, and directory-scan prefixes.
type GuardRuleDoc struct {
	Rules []struct {
		ID    string   `json:"id"`
		Paths []string `json:"paths"`
		Mode  string   `json:"mode"`
	} `json:"rules"`
	DirScan [][]string `json:"dir_scan"`
}

func ParseGuardRules(b []byte) (GuardRuleDoc, error) {
	var doc GuardRuleDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return GuardRuleDoc{}, err
	}
	if len(doc.Rules) == 0 {
		return GuardRuleDoc{}, fmt.Errorf("guard-rules.json: no rules")
	}
	return doc, nil
}

func globSafeForCorrelator(p string) bool {
	// sensitive.Classify matches filepath.Base(glob) against the file name.
	// A glob whose base is "*" or "**" (* as in ~/.azure/**) would mark every
	// file on disk sensitive.
	base := filepath.Base(filepath.Clean(p))
	return base != "*" && base != "**"
}

func mergeGuardRulePaths(raw *rawConfig) {
	doc, err := ParseGuardRules(guardRulesBytes)
	if err != nil {
		log.Printf("config: guard-rules.json: %v", err)
		return
	}
	seen := make(map[string]bool, len(raw.SensitiveGlobs)+16)
	for _, g := range raw.SensitiveGlobs {
		seen[g] = true
	}
	for _, r := range doc.Rules {
		for _, p := range r.Paths {
			if p == "" || seen[p] || !globSafeForCorrelator(p) {
				continue
			}
			raw.SensitiveGlobs = append(raw.SensitiveGlobs, p)
			seen[p] = true
		}
	}
	seenPath := make(map[string]bool, len(raw.SensitivePaths)+8)
	for _, p := range raw.SensitivePaths {
		seenPath[p] = true
	}
	for _, pair := range doc.DirScan {
		if len(pair) < 1 || pair[0] == "" || seenPath[pair[0]] {
			continue
		}
		raw.SensitivePaths = append(raw.SensitivePaths, pair[0])
		seenPath[pair[0]] = true
	}
}

type AgentDef struct {
	Name  string   `yaml:"name"`
	Match []string `yaml:"match"`
}

// FirewallConfig configures the egress secret-leak firewall (see the
// egress-secret-leak-firewall design doc).
type FirewallConfig struct {
	Mode     string                  `yaml:"mode"` // monitor | block (global default)
	Registry RegistryConfig          `yaml:"registry"`
	Patterns []PatternConfig         `yaml:"patterns"`
	Entropy  EntropyConfig           `yaml:"entropy"`
	Vendors  map[string]VendorConfig `yaml:"vendors"`
	Context  ContextConfig           `yaml:"context"`
}

type RegistryConfig struct {
	SaltRef       string        `yaml:"salt_ref"`
	IngestSources []string      `yaml:"ingest_sources"`
	Fingerprints  []Fingerprint `yaml:"fingerprints"`
}

type Fingerprint struct {
	ID    string `yaml:"id"`
	Type  string `yaml:"type"`
	Len   int    `yaml:"len"`
	Label string `yaml:"label"`
	HMAC  string `yaml:"hmac"`
}

type PatternConfig struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
	Re   string `yaml:"re"`
	Mode string `yaml:"mode"`
}

type EntropyConfig struct {
	Enabled bool    `yaml:"enabled"`
	MinLen  int     `yaml:"min_len"`
	MinBits float64 `yaml:"min_bits"`
	Mode    string  `yaml:"mode"`
}

type VendorConfig struct {
	Hosts      []string `yaml:"hosts"`
	AuthHeader string   `yaml:"auth_header"`
}

type ContextConfig struct {
	AllowOwnVendorAuth    bool `yaml:"allow_own_vendor_auth"`
	TreatBodySecretAsLeak bool `yaml:"treat_body_secret_as_leak"`
}

// WebhookConfig is one HMAC-signed fleet sink.
type WebhookConfig struct {
	URL    string   `yaml:"url"`
	Secret string   `yaml:"secret"`
	Events []string `yaml:"events"` // flag | incident | guard; empty = all
}

// FleetConfig configures downstream fleet-oversight delivery.
type FleetConfig struct {
	Webhooks []WebhookConfig `yaml:"webhooks"`
	// Hostname overrides os.Hostname() in status envelopes — the display name
	// collectors show for this node.
	Hostname string `yaml:"hostname"`
	// Labels are operator-defined grouping dimensions (env, role, team…)
	// carried in status envelopes for multi-fleet views.
	Labels map[string]string `yaml:"labels"`
	// HeartbeatIntervalSec is the status-envelope cadence (default 60s).
	// Posture-state transitions always push immediately regardless.
	HeartbeatIntervalSec int `yaml:"heartbeat_interval_sec"`
}

// CwdOverride pins one directory subtree to specific guard-rule modes — the
// per-project policy layer (deny .env in the production repo, monitor
// everywhere else). Written to guard-cwd-overrides.json for the hook to read.
type CwdOverride struct {
	CwdPrefix string            `yaml:"cwd_prefix"`
	Rules     map[string]string `yaml:"rules"` // rule_id -> monitor|prompt|deny
}

// DirectoryGuardConfig configures the interactive filesystem guard (pillar 2).
// The hook owns the rule set — it is a stdlib-only Python process and cannot
// parse YAML — via its own embedded copy plus the user's guard-modes.json
// override file. The daemon config carries only the hook's fail-safe prompt
// deadline.
type DirectoryGuardConfig struct {
	PromptDeadlineMS int           `yaml:"prompt_deadline_ms"`
	CwdOverrides     []CwdOverride `yaml:"cwd_overrides"`
}

// ResourceControlConfig governs whole attributed session families. Zero
// limits disable that dimension. Termination is never a default: operators
// must explicitly select mode=terminate in their private config overlay.
type ResourceControlConfig struct {
	Mode               string                       `yaml:"mode" json:"mode"` // observe | prompt | terminate
	MaxRSSMB           uint64                       `yaml:"max_rss_mb" json:"max_rss_mb"`
	MaxCPUPercent      float64                      `yaml:"max_cpu_percent" json:"max_cpu_percent"`
	SustainSeconds     int                          `yaml:"sustain_seconds" json:"sustain_seconds"`
	CooldownSeconds    int                          `yaml:"cooldown_seconds" json:"cooldown_seconds"`
	Interventions      []ResourceInterventionConfig `yaml:"interventions,omitempty" json:"interventions,omitempty"`
	WorkspaceOverrides []ResourceControlOverride    `yaml:"workspace_overrides,omitempty" json:"workspace_overrides"`
}

type ResourceInterventionConfig struct {
	Action       string `yaml:"action" json:"action"`
	AfterSeconds int    `yaml:"after_seconds" json:"after_seconds"`
	Nice         int    `yaml:"nice,omitempty" json:"nice,omitempty"`
}

// ResourceControlOverride applies a complete policy to one workspace subtree.
// Complete policies make the effective behavior reviewable without hidden
// field inheritance from the machine default.
type ResourceControlOverride struct {
	CwdPrefix       string                       `yaml:"cwd_prefix" json:"cwd_prefix"`
	Mode            string                       `yaml:"mode" json:"mode"`
	MaxRSSMB        uint64                       `yaml:"max_rss_mb" json:"max_rss_mb"`
	MaxCPUPercent   float64                      `yaml:"max_cpu_percent" json:"max_cpu_percent"`
	SustainSeconds  int                          `yaml:"sustain_seconds" json:"sustain_seconds"`
	CooldownSeconds int                          `yaml:"cooldown_seconds" json:"cooldown_seconds"`
	Interventions   []ResourceInterventionConfig `yaml:"interventions,omitempty" json:"interventions,omitempty"`
}

// AdvisorYAML is the on-disk shape of the local advisor config.
type AdvisorYAML struct {
	Enabled      bool   `yaml:"enabled"`
	Endpoint     string `yaml:"endpoint"`
	Model        string `yaml:"model"`
	TimeoutMS    int    `yaml:"timeout_ms"`
	Managed      bool   `yaml:"managed"`
	ManagedModel string `yaml:"managed_model"`
}

// AdvisorConfig configures the local triage advisor. Disabled unless
// explicitly opted in; the endpoint must be loopback (the privacy guarantee
// is enforced at validation time and again at client construction).
// Managed mode: the daemon spawns/supervises the model server itself and
// computes the endpoint — Endpoint is ignored (and must not be set).
type AdvisorConfig struct {
	Enabled      bool
	Endpoint     string
	Model        string
	Timeout      time.Duration
	Managed      bool
	ManagedModel string
}

type rawConfig struct {
	DisabledAgents      []string              `yaml:"disabled_agents"`
	SensitiveGlobs      []string              `yaml:"sensitive_globs"`
	SensitivePaths      []string              `yaml:"sensitive_paths"`
	KeychainMarkers     []string              `yaml:"keychain_markers"`
	Agents              []AgentDef            `yaml:"agents"`
	VendorAllowlist     map[string][]string   `yaml:"vendor_allowlist"`
	NetSampleIntervalMS int64                 `yaml:"net_sample_interval_ms"`
	SocketPath          string                `yaml:"socket_path"`
	DBPath              string                `yaml:"db_path"`
	JSONLPath           string                `yaml:"jsonl_path"`
	ProxyEnabled        bool                  `yaml:"proxy_enabled"`
	ProxyPort           int                   `yaml:"proxy_port"`
	ProxyCACertPath     string                `yaml:"proxy_ca_cert_path"`
	ProxyCAKeyPath      string                `yaml:"proxy_ca_key_path"`
	Firewall            FirewallConfig        `yaml:"firewall"`
	DirectoryGuard      DirectoryGuardConfig  `yaml:"directory_guard"`
	ResourceControl     ResourceControlConfig `yaml:"resource_control"`
	Fleet               FleetConfig           `yaml:"fleet"`
	Advisor             AdvisorYAML           `yaml:"advisor"`
}

type Config struct {
	SensitiveGlobs    []string
	SensitivePaths    []string
	KeychainMarkers   []string
	Agents            []AgentDef
	VendorAllowlist   map[string][]string
	DisabledAgents    []string
	NetSampleInterval time.Duration
	SocketPath        string
	DBPath            string
	JSONLPath         string
	ProxyEnabled      bool
	ProxyPort         int
	ProxyCACertPath   string
	ProxyCAKeyPath    string
	Firewall          FirewallConfig
	DirectoryGuard    DirectoryGuardConfig
	ResourceControl   ResourceControlConfig
	Fleet             FleetConfig
	Advisor           AdvisorConfig
}

// filterDisabledAgents drops agents the operator disabled via
// disabled_agents (case-insensitive name match) — the Providers settings
// writes this list. A name in disabled_agents that matches nothing is
// ignored (stale entries must not error).
func filterDisabledAgents(all []AgentDef, disabled []string) []AgentDef {
	if len(disabled) == 0 {
		return all
	}
	off := map[string]bool{}
	for _, d := range disabled {
		off[strings.ToLower(d)] = true
	}
	out := all[:0]
	for _, a := range all {
		if !off[strings.ToLower(a.Name)] {
			out = append(out, a)
		}
	}
	return out
}

// ErrOverlayMalformed is returned by LoadStrict when the user overlay exists
// but cannot be parsed. Load (lenient) masks it with compiled-in defaults —
// correct for startup, DANGEROUS for hot-reload: a half-written config would
// silently reconfigure the advisor to defaults. Callers that re-read a file
// that was just written must use LoadStrict and keep the previous state.
var ErrOverlayMalformed = fmt.Errorf("overlay is malformed YAML")

func LoadStrict(explicitPath string) (Config, error) {
	cfg, overlayErr, validateErr := loadWithOverlayError(explicitPath)
	if validateErr != nil {
		return Config{}, validateErr
	}
	if overlayErr != nil {
		return cfg, overlayErr
	}
	return cfg, nil
}

// Load is the lenient variant used at boot: a malformed overlay falls back
// to compiled-in defaults (logged), but VALIDATION errors still surface —
// booting with a sample interval that panics the collector is worse than
// refusing to start.
func Load(explicitPath string) (Config, error) {
	cfg, _, validateErr := loadWithOverlayError(explicitPath)
	if validateErr != nil {
		return Config{}, validateErr
	}
	return cfg, nil
}

// loadWithOverlayError returns the config AND whether the overlay was
// malformed (defaults were substituted). The hot-reload watcher uses this to
// distinguish "operator changed something" from "config was half-written".
func loadWithOverlayError(explicitPath string) (Config, error, error) {
	var raw rawConfig
	var overlayMalformed error
	if err := yaml.Unmarshal(defaultBytes, &raw); err != nil {
		return Config{}, err, err
	}
	mergeGuardRulePaths(&raw)

	targetPath := explicitPath
	if targetPath == "" || targetPath == "/nonexistent" {
		home, _ := os.UserHomeDir()
		if home != "" {
			defaultOverlay := filepath.Join(home, ".config", "secure-agent", "config.yaml")
			if _, err := os.Stat(defaultOverlay); err == nil {
				targetPath = defaultOverlay
			}
		}
	}

	if targetPath != "" && targetPath != "/nonexistent" {
		data, err := os.ReadFile(expandPath(targetPath))
		switch {
		case err != nil && !os.IsNotExist(err):
			// An overlay that exists but can't be read must not silently fall
			// back to defaults — the user's `mode: block` reverting to monitor
			// with no signal is exactly the failure this tool exists to prevent.
			log.Printf("config: WARNING: overlay %s unreadable (%v); running on compiled-in defaults", targetPath, err)
			overlayMalformed = err
		case err == nil:
			if err := yaml.Unmarshal(data, &raw); err != nil {
				log.Printf("config: WARNING: overlay %s is malformed YAML (%v); running on compiled-in defaults", targetPath, err)
				overlayMalformed = fmt.Errorf("%w: %v", ErrOverlayMalformed, err)
			}
		}
	}

	cfg := Config{
		SensitiveGlobs:    expandPaths(raw.SensitiveGlobs),
		SensitivePaths:    expandPaths(raw.SensitivePaths),
		KeychainMarkers:   raw.KeychainMarkers,
		Agents:            filterDisabledAgents(raw.Agents, raw.DisabledAgents),
		VendorAllowlist:   raw.VendorAllowlist,
		NetSampleInterval: time.Duration(raw.NetSampleIntervalMS) * time.Millisecond,
		SocketPath:        expandPath(raw.SocketPath),
		DBPath:            expandPath(raw.DBPath),
		JSONLPath:         expandPath(raw.JSONLPath),
		ProxyEnabled:      raw.ProxyEnabled,
		ProxyPort:         raw.ProxyPort,
		ProxyCACertPath:   expandPath(raw.ProxyCACertPath),
		ProxyCAKeyPath:    expandPath(raw.ProxyCAKeyPath),
		Firewall:          raw.Firewall,
		DirectoryGuard:    raw.DirectoryGuard,
		ResourceControl:   raw.ResourceControl,
		Fleet:             raw.Fleet,
		Advisor: AdvisorConfig{
			Enabled:      raw.Advisor.Enabled,
			Endpoint:     raw.Advisor.Endpoint,
			Model:        raw.Advisor.Model,
			Timeout:      time.Duration(raw.Advisor.TimeoutMS) * time.Millisecond,
			Managed:      raw.Advisor.Managed,
			ManagedModel: raw.Advisor.ManagedModel,
		},
	}
	for i := range cfg.ResourceControl.WorkspaceOverrides {
		cfg.ResourceControl.WorkspaceOverrides[i].CwdPrefix = expandPath(cfg.ResourceControl.WorkspaceOverrides[i].CwdPrefix)
	}
	if cfg.Advisor.Enabled && !cfg.Advisor.Managed && cfg.Advisor.Endpoint == "" {
		cfg.Advisor.Endpoint = "http://127.0.0.1:8080"
	}
	cfg.Firewall.Registry.SaltRef = expandPath(cfg.Firewall.Registry.SaltRef)
	cfg.Firewall.Registry.IngestSources = expandPaths(cfg.Firewall.Registry.IngestSources)

	if err := cfg.Validate(); err != nil {
		return Config{}, overlayMalformed, err
	}
	return cfg, overlayMalformed, nil
}

// Validate rejects values that would crash or silently break subsystems at
// runtime. A non-positive sample interval reaches time.NewTicker, which panics
// — the supervisor then recovers a permanently crash-looping collector.
func (c Config) Validate() error {
	if c.NetSampleInterval <= 0 {
		return fmt.Errorf("net_sample_interval_ms must be positive, got %d", c.NetSampleInterval.Milliseconds())
	}
	// Port 0 is valid: the kernel assigns a free port (the e2e harness and
	// tests use it), and ProxyServer.Serve reads back the bound port.
	if c.ProxyEnabled && (c.ProxyPort < 0 || c.ProxyPort > 65535) {
		return fmt.Errorf("proxy_port must be 0-65535, got %d", c.ProxyPort)
	}
	if c.DirectoryGuard.PromptDeadlineMS < 0 {
		return fmt.Errorf("directory_guard.prompt_deadline_ms must be >= 0, got %d", c.DirectoryGuard.PromptDeadlineMS)
	}
	if err := ValidateResourceControl(c.ResourceControl); err != nil {
		return err
	}
	if c.Fleet.HeartbeatIntervalSec < 0 {
		return fmt.Errorf("fleet.heartbeat_interval_sec must be >= 0, got %d", c.Fleet.HeartbeatIntervalSec)
	}
	// The advisor's privacy guarantee is enforced, not promised: it may only
	// talk to a loopback endpoint. Anything else is a config error, not a
	// fallback. Managed mode derives its endpoint (spawned server); a manual
	// one alongside it is a contradiction worth rejecting loudly.
	if c.Advisor.Enabled && c.Advisor.Managed {
		if c.Advisor.ManagedModel == "" {
			return fmt.Errorf("advisor.managed_model is required when advisor.managed is true")
		}
		if c.Advisor.Endpoint != "" {
			return fmt.Errorf("advisor.endpoint must not be set when advisor.managed is true (it is derived from the spawned server)")
		}
	} else if c.Advisor.Enabled {
		u, err := url.Parse(c.Advisor.Endpoint)
		if err != nil || u.Hostname() == "" {
			return fmt.Errorf("advisor.endpoint %q is not a valid URL", c.Advisor.Endpoint)
		}
		h := strings.ToLower(u.Hostname())
		ip := net.ParseIP(h)
		if h != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("advisor.endpoint must be loopback (127.0.0.1/::1/localhost), got %q", c.Advisor.Endpoint)
		}
	}
	return nil
}

// ValidateResourceControl validates both the machine default and every scoped
// policy. Workspace prefixes are path-boundary matched, so duplicates and
// non-canonical paths are rejected instead of producing ambiguous precedence.
func ValidateResourceControl(c ResourceControlConfig) error {
	if err := validateResourcePolicy("resource_control", c.Mode, c.MaxRSSMB, c.MaxCPUPercent, c.SustainSeconds, c.CooldownSeconds); err != nil {
		return err
	}
	if err := validateResourceInterventions("resource_control", c.Interventions); err != nil {
		return err
	}
	seen := make(map[string]bool, len(c.WorkspaceOverrides))
	for i, override := range c.WorkspaceOverrides {
		field := fmt.Sprintf("resource_control.workspace_overrides[%d]", i)
		if override.CwdPrefix == "" || !filepath.IsAbs(override.CwdPrefix) {
			return fmt.Errorf("%s.cwd_prefix must be an absolute path", field)
		}
		clean := filepath.Clean(override.CwdPrefix)
		if clean != override.CwdPrefix {
			return fmt.Errorf("%s.cwd_prefix must be normalized, got %q", field, override.CwdPrefix)
		}
		if seen[clean] {
			return fmt.Errorf("%s.cwd_prefix duplicates %q", field, clean)
		}
		seen[clean] = true
		if err := validateResourcePolicy(field, override.Mode, override.MaxRSSMB, override.MaxCPUPercent, override.SustainSeconds, override.CooldownSeconds); err != nil {
			return err
		}
		if err := validateResourceInterventions(field, override.Interventions); err != nil {
			return err
		}
	}
	return nil
}

func validateResourcePolicy(field, mode string, maxRSSMB uint64, maxCPU float64, sustain, cooldown int) error {
	switch mode {
	case "observe", "prompt", "terminate":
	default:
		return fmt.Errorf("%s.mode must be observe, prompt, or terminate, got %q", field, mode)
	}
	if maxCPU < 0 || math.IsNaN(maxCPU) || math.IsInf(maxCPU, 0) {
		return fmt.Errorf("%s.max_cpu_percent must be >= 0", field)
	}
	if maxRSSMB > ^uint64(0)/(1024*1024) {
		return fmt.Errorf("%s.max_rss_mb is too large", field)
	}
	if sustain < 0 || cooldown < 0 {
		return fmt.Errorf("%s sustain_seconds and cooldown_seconds must be >= 0", field)
	}
	const maxDurationSeconds = int64((1<<63 - 1) / int64(time.Second))
	if int64(sustain) > maxDurationSeconds || int64(cooldown) > maxDurationSeconds {
		return fmt.Errorf("%s sustain_seconds and cooldown_seconds are too large", field)
	}
	return nil
}

func validateResourceInterventions(field string, steps []ResourceInterventionConfig) error {
	seen := make(map[string]bool, len(steps))
	previousAfter := -1
	previousRank := -1
	rank := map[string]int{"notify": 0, "lower_priority": 1, "pause": 2, "terminate": 3}
	for i, step := range steps {
		stepField := fmt.Sprintf("%s.interventions[%d]", field, i)
		switch step.Action {
		case "notify", "lower_priority", "pause", "terminate":
		default:
			return fmt.Errorf("%s.action must be notify, lower_priority, pause, or terminate", stepField)
		}
		if seen[step.Action] {
			return fmt.Errorf("%s.action duplicates %q", stepField, step.Action)
		}
		seen[step.Action] = true
		if rank[step.Action] <= previousRank {
			return fmt.Errorf("%s.action must follow notify, lower_priority, pause, terminate order", stepField)
		}
		previousRank = rank[step.Action]
		if step.AfterSeconds < 0 || step.AfterSeconds < previousAfter {
			return fmt.Errorf("%s.after_seconds must be non-negative and ordered", stepField)
		}
		const maxDurationSeconds = int64((1<<63 - 1) / int64(time.Second))
		if int64(step.AfterSeconds) > maxDurationSeconds {
			return fmt.Errorf("%s.after_seconds is too large", stepField)
		}
		previousAfter = step.AfterSeconds
		if step.Action == "lower_priority" {
			if step.Nice < 1 || step.Nice > 19 {
				return fmt.Errorf("%s.nice must be between 1 and 19", stepField)
			}
		} else if step.Nice != 0 {
			return fmt.Errorf("%s.nice is only valid for lower_priority", stepField)
		}
		if step.Action == "terminate" && i != len(steps)-1 {
			return fmt.Errorf("%s terminate must be the final intervention", stepField)
		}
	}
	return nil
}

// ExpandPath expands a leading ~ and $ENV references in p, matching how config
// sources are normalized at load. Exported for runtime-added ingest sources,
// which are stored raw and expanded at use.
func ExpandPath(p string) string { return expandPath(p) }

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return os.ExpandEnv(p)
}

func expandPaths(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = expandPath(p)
	}
	return out
}
