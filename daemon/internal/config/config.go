package config

import (
	_ "embed"
	"fmt"
	"log"
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
	DisabledAgents      []string             `yaml:"disabled_agents"`
	SensitiveGlobs      []string             `yaml:"sensitive_globs"`
	SensitivePaths      []string             `yaml:"sensitive_paths"`
	KeychainMarkers     []string             `yaml:"keychain_markers"`
	Agents              []AgentDef           `yaml:"agents"`
	VendorAllowlist     map[string][]string  `yaml:"vendor_allowlist"`
	NetSampleIntervalMS int64                `yaml:"net_sample_interval_ms"`
	SocketPath          string               `yaml:"socket_path"`
	DBPath              string               `yaml:"db_path"`
	JSONLPath           string               `yaml:"jsonl_path"`
	ProxyEnabled        bool                 `yaml:"proxy_enabled"`
	ProxyPort           int                  `yaml:"proxy_port"`
	ProxyCACertPath     string               `yaml:"proxy_ca_cert_path"`
	ProxyCAKeyPath      string               `yaml:"proxy_ca_key_path"`
	Firewall            FirewallConfig       `yaml:"firewall"`
	DirectoryGuard      DirectoryGuardConfig `yaml:"directory_guard"`
	Fleet               FleetConfig          `yaml:"fleet"`
	Advisor             AdvisorYAML          `yaml:"advisor"`
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

func Load(explicitPath string) (Config, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(defaultBytes, &raw); err != nil {
		return Config{}, err
	}

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
		case err == nil:
			if err := yaml.Unmarshal(data, &raw); err != nil {
				log.Printf("config: WARNING: overlay %s is malformed YAML (%v); running on compiled-in defaults", targetPath, err)
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
	if cfg.Advisor.Enabled && !cfg.Advisor.Managed && cfg.Advisor.Endpoint == "" {
		cfg.Advisor.Endpoint = "http://127.0.0.1:8080"
	}
	cfg.Firewall.Registry.SaltRef = expandPath(cfg.Firewall.Registry.SaltRef)
	cfg.Firewall.Registry.IngestSources = expandPaths(cfg.Firewall.Registry.IngestSources)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
